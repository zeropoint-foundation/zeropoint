//! Discipline: a repo-managed state file that is *read* must be *written*
//! somewhere in the tree.
//!
//! # Why (2026-08-17)
//!
//! `.githooks/pre-commit` decides whether to warn that `just check` is stale by
//! reading `$GIT_DIR/zp-last-check` — its modification time for the age
//! backstop, its first line for the toolchain-change check. Nothing in the tree
//! wrote that file. One read site, zero write sites, marker absent on disk.
//!
//! So from 2026-08-12 the hook printed
//!
//! ```text
//! pre-commit: NOTE — 'just check' has no recorded successful run.
//! ```
//!
//! on every commit, unconditionally, including immediately after a successful
//! run. Worse than the noise: both real detectors live in the `else` branch
//! taken when the marker exists, so **neither could ever be entered**. The
//! toolchain-change check — which the hook's own comment identifies as the
//! useful half, because the ~60 unread clippy diagnostics of 2026-08-12
//! accumulated when clippy got newer rather than when time passed, and one of
//! them was CROSS-USER-01 — had never once been able to fire.
//!
//! # Why this shape is worth a pin
//!
//! It is the fourth instance this month of the same defect: code that reads as
//! governed and whose check cannot fail. `delegation_expired` unreachable
//! behind a `None` expiry (`PERENNIAL-GRANT-2026-08`), `zp-anchor` declaring a
//! default backend the server never constructed, `ARCHITECTURE.md`'s
//! structural-bypass claim one `use` away from false.
//!
//! Three of those were found by someone reading for them. **This one announced
//! itself in the terminal on every commit for five days and read as normal**,
//! because a warning that is always on is indistinguishable from a warning that
//! is working until you move its input. That is what makes it worth automating:
//! it is the member of the class least likely to be caught by attention.
//!
//! # What this asserts, and what it deliberately does not
//!
//! For every repo-managed state path that has at least one **read** site in the
//! shell surface, there must be at least one **write** site.
//!
//! The converse is not asserted. A write-only file is a log, not a defect —
//! `${HOME}/.cache/graphify-rebuild.log` is written by two hooks and read by no
//! one, which is exactly right for a log.
//!
//! That log is also the first thing this pin got wrong, and the correction is
//! recorded in [`uses`] rather than quietly fixed: the initial classifier asked
//! whether a *line* contained a redirection rather than what stood immediately
//! before the variable, and reported the log as read-with-no-writer. A pin's
//! first false positive is the moment it either earns trust or loses it, so the
//! shape that caused it is now a test.
//!
//! Scope is limited to paths under roots nothing outside this repository writes
//! (see `STATE_ROOTS`). Deliberately excluded: `$HOME/ZeroPoint/...`,
//! `target/...`, `~/Library/...`, and similar — those are written by the `zp`
//! binary at runtime, by cargo, or by the operator, and a shell script reading
//! one is reading someone else's output rather than its own. Widening the roots
//! would turn this pin into a list of exceptions, and a pin that is mostly
//! exceptions is the thing this pin exists to catch.
//!
//! # On the verification harness
//!
//! `scripts/verify-check-staleness.sh` is excluded from the scan entirely, and
//! the exclusion is load-bearing rather than tidy. That script writes the very
//! marker it verifies. Counting it as a writer would let this pin pass while
//! the production writer in `Justfile` was missing — which is precisely the
//! defect being guarded, reintroduced inside its own guard. Excluding it from
//! *reads* as well keeps the rule symmetric and the reasoning simple: the
//! harness is not part of the surface under test.
//!
//! # On parser drift
//!
//! This pin parses shell variable bindings of the form `VAR="$DIR/name"`. A
//! state file introduced by some other spelling — built by string concatenation
//! at the point of use, say — will not be seen. That is a known limit, not a
//! silent one: `the_scan_actually_finds_the_known_bindings` fails loudly if the
//! one binding we know about stops being found. **Fix the parser; do not delete
//! the pin.**

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Files scanned. The operator-facing shell surface: git hooks, the task
/// runner, and repository scripts.
const SCAN_DIRS: &[&str] = &[".githooks", "scripts"];
const SCAN_FILES: &[&str] = &["Justfile"];

/// Path prefixes that denote state this repository manages itself. Nothing
/// outside the repo writes here, so "read with no writer" is unambiguous.
const STATE_ROOTS: &[&str] = &[
    "$GIT_DIR",
    "${GIT_DIR}",
    ".git/",
    "$HOME/.cache",
    "${HOME}/.cache",
];

/// Excluded from the scan; see the module docs — this is not tidiness.
const NOT_UNDER_TEST: &[&str] = &["verify-check-staleness.sh"];

/// The binding this pin is known to catch. If this disappears from the scan,
/// the parser has drifted and the pin is silently guarding nothing.
const KNOWN_BINDING: &str = "zp-last-check";

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    while !p.join("Cargo.lock").exists() {
        if !p.pop() {
            panic!("could not locate workspace root from cwd");
        }
    }
    p
}

/// Every file in the shell surface, as (display path, contents).
fn surface(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut push = |path: &Path| {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if NOT_UNDER_TEST.contains(&name) {
            return;
        }
        if let Ok(body) = fs::read_to_string(path) {
            let shown = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            out.push((shown, body));
        }
    };
    for d in SCAN_DIRS {
        if let Ok(entries) = fs::read_dir(root.join(d)) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_file() {
                    push(&p);
                }
            }
        }
    }
    for f in SCAN_FILES {
        let p = root.join(f);
        if p.is_file() {
            push(&p);
        }
    }
    out
}

/// A shell binding of a state path: `MARKER="$GIT_DIR/zp-last-check"`.
///
/// Returns (variable name, file-name component). The file-name component is
/// the key used across files, because the writer and the reader routinely
/// live in different files — in the defect that motivated this pin they were
/// `Justfile` and `.githooks/pre-commit`.
fn state_bindings(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let Some((lhs, rhs)) = t.split_once('=') else {
            continue;
        };
        let var = lhs.trim();
        if var.is_empty() || !var.chars().all(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let value = rhs.trim().trim_matches('"');
        if !STATE_ROOTS.iter().any(|r| value.starts_with(r)) {
            continue;
        }
        if let Some((_, name)) = value.rsplit_once('/') {
            if !name.is_empty() && !name.contains('$') {
                out.push((var.to_string(), name.to_string()));
            }
        }
    }
    out
}

/// How a single occurrence of a variable is being used.
#[derive(Debug, PartialEq, Eq)]
enum Use {
    Read,
    Write,
    /// Named but not touched — `echo "log: $VAR"`.
    Mention,
}

const READ_VERBS: &[&str] = &[
    "cat ", "head ", "tail ", "sed ", "grep ", "awk ", "find ", "wc ", "source ",
];
const READ_TESTS: &[&str] = &["-f ", "-e ", "-s ", "-r ", "-nt ", "-ot "];

/// Classify every occurrence of `$var` / `${var}` on a line.
///
/// **Position, not presence.** The first cut of this pin asked whether the line
/// contained a `<` or a `>` anywhere, and got both of the graphify hooks'
/// redirection lines wrong in opposite directions at once:
///
/// ```text
/// " > "$_GRAPHIFY_LOG" 2>&1 < /dev/null &
/// ```
///
/// The `< /dev/null` made it read as a *read* of the log, and a veto on
/// `2>&1` — meant to stop stderr redirection counting as a file write —
/// cancelled the real `>` that precedes the variable. Net effect: a write-only
/// log was reported as read-with-no-writer, the exact false positive that would
/// have taught the next reader to stop trusting this pin.
///
/// So the operator is now read off the text *immediately preceding the
/// occurrence*, and `/dev/null` at the far end of the line is correctly none of
/// this pin's business.
fn uses(line: &str, var: &str) -> Vec<Use> {
    let mut out = Vec::new();
    let last_dollar = line.rfind('$');
    for form in [format!("${var}"), format!("${{{var}}}")] {
        let mut from = 0usize;
        while let Some(rel) = line[from..].find(form.as_str()) {
            let at = from + rel;
            from = at + form.len();

            // `$MARKER_OTHER` is not `$MARKER`.
            let after = line[from..].chars().next();
            if !form.ends_with('}') && matches!(after, Some(c) if c.is_alphanumeric() || c == '_') {
                continue;
            }

            let prefix = &line[..at];
            // Step back over the quoting and spacing between the operator and
            // the variable: `> "$VAR"`, `>"$VAR"`, `> $VAR` are one case.
            let adjacent = prefix.trim_end().trim_end_matches(['"', '\'']).trim_end();

            if adjacent.ends_with('>') {
                out.push(Use::Write);
            } else if adjacent.ends_with('<') && !adjacent.ends_with("<<") {
                out.push(Use::Read);
            } else if prefix.contains("cp ") || prefix.contains("mv ") {
                // Destination is the final argument; anything earlier is a
                // source being read.
                if last_dollar == Some(at) {
                    out.push(Use::Write);
                } else {
                    out.push(Use::Read);
                }
            } else if prefix.contains("touch ") || prefix.contains("tee ") {
                out.push(Use::Write);
            } else if READ_VERBS.iter().any(|v| prefix.contains(v))
                || READ_TESTS.iter().any(|t| prefix.contains(t))
            {
                out.push(Use::Read);
            } else {
                out.push(Use::Mention);
            }
        }
    }
    out
}

fn is_read(line: &str, var: &str) -> bool {
    uses(line, var).contains(&Use::Read)
}

fn is_write(line: &str, var: &str) -> bool {
    uses(line, var).contains(&Use::Write)
}

/// State file name -> (files that read it, files that write it).
///
/// A literal occurrence of the name in a redirection also counts as a write,
/// which is how `Justfile`'s one-line stamp is seen: it never binds a
/// variable, it redirects straight into the composed path.
fn read_and_write_sites(root: &Path) -> BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> {
    let files = surface(root);
    let mut sites: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();

    // Pass one: every state file name known anywhere in the surface.
    let mut names: BTreeSet<String> = BTreeSet::new();
    for (_, body) in &files {
        for (_, name) in state_bindings(body) {
            names.insert(name);
        }
    }

    // Pass two: classify each file's use of each name, via its local binding
    // or via the literal.
    for (path, body) in &files {
        let bindings = state_bindings(body);
        for name in &names {
            let vars: Vec<String> = bindings
                .iter()
                .filter(|(_, n)| n == name)
                .map(|(v, _)| v.clone())
                .collect();
            for line in body.lines() {
                let t = line.trim();
                if t.starts_with('#') {
                    continue;
                }
                let entry = sites.entry(name.clone()).or_default();
                if let Some(at) = t.find(name.as_str()) {
                    // Literal use — `Justfile` redirects straight into the
                    // composed path without ever binding a variable. Adjacency
                    // cannot be used here (the literal's left neighbour is a
                    // `/`), so require a redirection somewhere *before* it,
                    // which still excludes the binding line itself.
                    if t[..at].contains('>') && !t.contains("<<") {
                        entry.1.insert(path.clone());
                    }
                }
                for v in &vars {
                    if is_write(t, v) {
                        entry.1.insert(path.clone());
                    }
                    if is_read(t, v) {
                        entry.0.insert(path.clone());
                    }
                }
            }
        }
    }
    sites
}

#[test]
fn every_read_state_file_has_a_writer() {
    let root = repo_root();
    let sites = read_and_write_sites(&root);

    let mut orphaned = Vec::new();
    for (name, (readers, writers)) in &sites {
        if !readers.is_empty() && writers.is_empty() {
            orphaned.push(format!(
                "{name}: read by {:?}, written by nothing",
                readers.iter().collect::<Vec<_>>()
            ));
        }
    }

    assert!(
        orphaned.is_empty(),
        "state files that are read but never written:\n  {}\n\n\
         A reader with no writer does not fail — it takes the same branch \
         forever, and every branch behind the other case is unreachable. This \
         is what `$GIT_DIR/zp-last-check` did from 2026-08-12 to 2026-08-17: \
         the staleness warning fired on every commit and its two real \
         detectors could never be entered.\n\
         Give the path a writer, or stop reading it. Adding an exception here \
         is an authority decision, not a lint fix.",
        orphaned.join("\n  ")
    );
}

/// The parser must still find the binding this pin was written for.
///
/// Without this, a rename or a reshaping of the hook would leave the pin
/// scanning nothing and reporting success — a pin that reads as governed and
/// cannot fail, which is the exact defect it exists to catch.
#[test]
fn the_scan_actually_finds_the_known_bindings() {
    let root = repo_root();
    let sites = read_and_write_sites(&root);

    let entry = sites.get(KNOWN_BINDING).unwrap_or_else(|| {
        panic!(
            "`{KNOWN_BINDING}` was not found in the shell surface. This pin parses \
             bindings of the form VAR=\"$DIR/name\" under {STATE_ROOTS:?}. If the \
             marker was renamed, moved, or now built by string concatenation at \
             the point of use, update the parser — do not delete the pin."
        )
    });

    assert!(
        !entry.0.is_empty(),
        "`{KNOWN_BINDING}` has no read site; the parser no longer sees \
         .githooks/pre-commit reading it"
    );
    assert!(
        !entry.1.is_empty(),
        "`{KNOWN_BINDING}` has no write site; the Justfile stamp added on \
         2026-08-17 is gone or no longer recognised"
    );
}

/// The classifier must separate the three cases on synthetic input.
///
/// A pin whose scanner cannot tell a read from a write from a mention would
/// pass on anything.
#[test]
fn the_scan_separates_reads_writes_and_mentions() {
    let binding = r#"MARKER="$GIT_DIR/some-state""#;
    assert_eq!(
        state_bindings(binding),
        vec![("MARKER".to_string(), "some-state".to_string())]
    );

    // A mention is not a read. This is the case that would have made the pin
    // vacuous: the graphify hooks echo their log path in a message.
    assert!(!is_read(r#"echo "writing to $MARKER""#, "MARKER"));
    assert!(!is_write(r#"echo "writing to $MARKER""#, "MARKER"));

    // Reads, in the spellings .githooks/pre-commit actually uses.
    assert!(is_read(r#"if [ ! -f "$MARKER" ]; then"#, "MARKER"));
    assert!(is_read(r#"LAST="$(head -n 1 "$MARKER")""#, "MARKER"));
    assert!(is_read(
        r#"if [ -n "$(find "$MARKER" -mtime +7)" ]; then"#,
        "MARKER"
    ));

    // Writes.
    assert!(is_write(r#"printf '%s\n' "$V" > "$MARKER""#, "MARKER"));
    assert!(is_write(r#"touch -t 202601010000 "$MARKER""#, "MARKER"));

    // `cp SRC DST` is a read of the source and a write of the destination.
    // Calling it a write of both would let a backup-and-restore harness
    // satisfy the pin for a file nothing else writes.
    assert!(is_read(r#"cp "$MARKER" "$BACKUP""#, "MARKER"));
    assert!(!is_write(r#"cp "$MARKER" "$BACKUP""#, "MARKER"));
    assert!(is_write(r#"cp "$MARKER" "$BACKUP""#, "BACKUP"));

    // The line that broke the first cut of this pin, in both directions at
    // once: a real write that a `2>&1` veto cancelled, and a `< /dev/null`
    // at the far end of the line that read as a read of the log.
    let graphify = r#"" > "$_GRAPHIFY_LOG" 2>&1 < /dev/null &"#;
    assert!(
        is_write(graphify, "_GRAPHIFY_LOG"),
        "the redirection immediately before the variable is a write, whatever \
         else appears later on the line"
    );
    assert!(
        !is_read(graphify, "_GRAPHIFY_LOG"),
        "`< /dev/null` reads /dev/null, not this variable"
    );

    // A variable whose name merely starts with another's is not the same file.
    assert!(!is_read(r#"cat "$MARKER_OTHER""#, "MARKER"));
}

/// The assertion must actually fire on a planted defect.
#[test]
fn a_read_with_no_writer_is_caught() {
    // The exact shape of the 2026-08-12 hook: bound, tested, parsed, never
    // written.
    let body = "\
MARKER=\"$GIT_DIR/orphan-state\"
if [ ! -f \"$MARKER\" ]; then
    echo stale
else
    LAST=\"$(head -n 1 \"$MARKER\")\"
fi
";
    let bindings = state_bindings(body);
    assert_eq!(bindings.len(), 1, "the binding must be found");

    let var = &bindings[0].0;
    let reads = body.lines().filter(|l| is_read(l.trim(), var)).count();
    let writes = body.lines().filter(|l| is_write(l.trim(), var)).count();

    assert!(reads > 0, "the planted reads must be seen");
    assert_eq!(
        writes, 0,
        "the planted defect has no writer; if this counts one, the write \
         classifier is too loose and the pin will pass on the real thing"
    );
}
