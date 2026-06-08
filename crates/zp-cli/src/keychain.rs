//! `zp keychain cleanup` — list and remove orphan OS Keychain entries.

use std::io::{self, Write};

/// Run the `zp keychain cleanup` command.
///
/// Default (dry-run): scans for orphan entries and prints what would be
/// deleted, without touching anything.
///
/// With `delete = true`: shows the same list, asks for explicit confirmation,
/// then deletes only the confirmed entries. Auto-delete on first invocation
/// is intentionally forbidden — operators must review before removing.
///
/// Returns a process exit code (0 = success, 1 = error).
pub fn run_cleanup(delete: bool) -> i32 {
    let found = zp_keys::find_orphan_keychain_entries();

    if found.is_empty() {
        println!();
        println!("  \x1b[32m✓\x1b[0m  No orphan ZeroPoint Keychain entries found.");
        println!();
        println!(
            "  Only the legitimate \x1b[1mzeropoint-genesis\x1b[0m sovereign root is present."
        );
        println!();
        return 0;
    }

    println!();
    println!("  Orphan ZeroPoint Keychain entries found:");
    println!();
    for (i, entry) in found.iter().enumerate() {
        println!(
            "  {}. service=\x1b[1m{}\x1b[0m  account=\x1b[1m{}\x1b[0m",
            i + 1,
            entry.service,
            entry.account
        );
        // Word-wrap the reason at ~70 chars for readability
        for line in wrap(entry.reason, 68) {
            println!("     {}", line);
        }
        println!();
    }

    if !delete {
        println!("  Dry run — no entries were modified.");
        println!();
        println!("  Run \x1b[1mzp keychain cleanup --delete\x1b[0m to remove them.");
        println!("  The legitimate \x1b[1mzeropoint-genesis\x1b[0m entry is never touched.");
        println!();
        return 0;
    }

    // --delete path: require explicit confirmation
    print!(
        "  Delete {} orphan entr{}? [y/N]: ",
        found.len(),
        if found.len() == 1 { "y" } else { "ies" }
    );
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() || input.trim().to_lowercase() != "y" {
        println!();
        println!("  Aborted — no entries were deleted.");
        println!();
        return 0;
    }
    println!();

    let mut any_error = false;
    for entry in &found {
        match zp_keys::delete_keychain_entry(entry.service, entry.account) {
            Ok(()) => {
                println!(
                    "  \x1b[32m✓\x1b[0m  Deleted: {}/{}",
                    entry.service, entry.account
                );
            }
            Err(e) => {
                eprintln!(
                    "  \x1b[31m✗\x1b[0m  Failed to delete {}/{}: {}",
                    entry.service, entry.account, e
                );
                any_error = true;
            }
        }
    }
    println!();

    if any_error {
        1
    } else {
        println!(
            "  \x1b[32m✓\x1b[0m  Cleanup complete. \x1b[1mzeropoint-genesis\x1b[0m is untouched."
        );
        println!();
        0
    }
}

/// Naïve word-wrap: split `text` into lines of at most `width` chars,
/// breaking on whitespace boundaries.
fn wrap(text: &str, width: usize) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let remaining = &text[start..];
        if remaining.len() <= width {
            lines.push(remaining);
            break;
        }
        // Find last space at or before `width`
        let cut = remaining[..width]
            .rfind(' ')
            .map(|i| i + 1) // start next line after the space
            .unwrap_or(width); // no space found — hard break
        lines.push(remaining[..cut].trim_end());
        start += cut;
        // Skip leading spaces on the next segment
        while start < text.len() && text.as_bytes()[start] == b' ' {
            start += 1;
        }
    }
    lines
}
