#!/usr/bin/env python3
"""Add SKIP tool events to backend so skipped tools show honestly in UI."""

path = "crates/zp-server/src/onboard.rs"
with open(path) as f:
    src = f.read()

old = '''                // Emit per-tool events so the UI can animate each card
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    // Parse lines like "  CONFIG openmaictool (/Users/.../openmaictool)"
                    // or "  \\u{2713} openmaictool \\u{2014} configured"
                    if trimmed.starts_with("CONFIG") || trimmed.starts_with("\\u{2713}") {
                        // Extract tool name (second word usually)
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let tool_name = parts[1].trim_end_matches(':');
                            events.push(OnboardEvent::new(
                                "tool_configured",
                                serde_json::json!({
                                    "tool_name": tool_name,
                                    "status": "governed",
                                }),
                            ));
                        }
                    }
                }'''

new = '''                // Emit per-tool events so the UI can animate each card
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("CONFIG") {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let tool_name = parts[1].trim_end_matches(':');
                            events.push(OnboardEvent::new(
                                "tool_configured",
                                serde_json::json!({
                                    "tool_name": tool_name,
                                    "status": "governed",
                                }),
                            ));
                        }
                    } else if trimmed.starts_with("SKIP") {
                        // Parse: "SKIP  toolname — missing N credential(s)"
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let tool_name = parts[1].trim_end_matches(':');
                            let missing = trimmed
                                .split("missing ")
                                .nth(1)
                                .and_then(|s| s.split_whitespace().next())
                                .and_then(|n| n.parse::<usize>().ok())
                                .unwrap_or(0);
                            events.push(OnboardEvent::new(
                                "tool_configured",
                                serde_json::json!({
                                    "tool_name": tool_name,
                                    "status": "skipped",
                                    "missing": missing,
                                }),
                            ));
                        }
                    }
                }'''

# Try the original unicode-escaped version first
if old in src:
    src = src.replace(old, new)
    with open(path, "w") as f:
        f.write(src)
    print("✓ Patched: added SKIP tool events")
else:
    # Try the version with literal ✓ character
    old2 = old.replace('\\u{2713}', '\u2713').replace('\\u{2014}', '\u2014')
    if old2 in src:
        src = src.replace(old2, new)
        with open(path, "w") as f:
            f.write(src)
        print("✓ Patched: added SKIP tool events (literal chars)")
    elif 'SKIP' in src and 'status": "skipped"' in src:
        print("Already patched — SKIP events present")
    else:
        print("✗ Could not find old block. Checking what's there...")
        # Find the emit section
        import re
        m = re.search(r'Emit per-tool events.*?^\s{16}\}', src, re.MULTILINE | re.DOTALL)
        if m:
            print(f"  Found emit block at offset {m.start()}")
            print(f"  First 200 chars: {m.group()[:200]}")
        else:
            print("  Could not find emit block at all")
