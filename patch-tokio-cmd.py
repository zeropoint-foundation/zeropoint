#!/usr/bin/env python3
"""Switch handle_configure from blocking std::process::Command to async tokio::process::Command."""

path = "crates/zp-server/src/onboard.rs"
with open(path) as f:
    src = f.read()

changes = 0

# 1. Add debug binary line (if not already present)
if 'events.push(OnboardEvent::terminal(&format!("Binary: {}"' not in src:
    src = src.replace(
        '    let zp_bin = which::which("zp").unwrap_or_else(|_| std::path::PathBuf::from("zp"));\n\n    // Run the configure engine',
        '    let zp_bin = which::which("zp").unwrap_or_else(|_| std::path::PathBuf::from("zp"));\n\n    events.push(OnboardEvent::terminal(&format!("Binary: {}", zp_bin.display())));\n\n    // Run the configure engine (async)',
    )
    changes += 1

# 2. Switch std::process::Command → tokio::process::Command
if 'std::process::Command::new(&zp_bin)' in src:
    src = src.replace('std::process::Command::new(&zp_bin)', 'tokio::process::Command::new(&zp_bin)')
    changes += 1

# 3. Add .await after .output()
if '.output()\n    {' in src:
    src = src.replace('.output()\n    {', '.output()\n        .await\n    {')
    changes += 1

# 4. Add empty-output detection (if not already present)
if '(no output from zp configure)' not in src:
    src = src.replace(
        '            if output.status.success() {',
        '            if stdout.is_empty() && stderr.is_empty() {\n                events.push(OnboardEvent::terminal("(no output from zp configure)"));\n            }\n\n            if output.status.success() {',
        1  # only first occurrence
    )
    changes += 1

with open(path, "w") as f:
    f.write(src)

print(f"Applied {changes} change(s)." if changes > 0 else "Already patched — no changes needed.")
