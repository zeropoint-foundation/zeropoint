#!/usr/bin/env python3
"""Final patch: fix --path arg in configure handler."""

path = "crates/zp-server/src/onboard.rs"
with open(path) as f:
    src = f.read()

old = '''    let mut cmd_args = vec![
        "configure".to_string(),
        "auto".to_string(),
        expanded_path.clone(),
        "--overwrite".to_string(),
    ];'''

new = '''    let mut cmd_args = vec![
        "configure".to_string(),
        "auto".to_string(),
        "--path".to_string(),
        expanded_path.clone(),
        "--overwrite".to_string(),
    ];'''

if old in src:
    src = src.replace(old, new)
    with open(path, "w") as f:
        f.write(src)
    print("✓ Added --path flag to configure auto command")
elif new in src:
    print("Already patched — --path flag present")
else:
    print("✗ Could not find the cmd_args block")
