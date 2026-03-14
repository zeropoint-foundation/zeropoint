//! `zp policy` subcommand — manage WASM policy modules.
//!
//! Provides CLI operations for loading, listing, enabling/disabling,
//! and inspecting WASM policy modules. Also supports auto-discovery
//! from `~/.zeropoint/policies/`.

use std::path::PathBuf;

use zp_policy::{PolicyModuleRegistry, WasmModuleMetadata};

use crate::commands::resolve_zp_home;

// ANSI colors (matching the rest of the CLI)
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const NC: &str = "\x1b[0m";

/// Policy module directory, resolved through the ZP_HOME chain.
fn default_policy_dir() -> PathBuf {
    resolve_zp_home().join("policies")
}

// ────────────────────────────────────────────────────────────────
// Subcommand: zp policy load <file.wasm>
// ────────────────────────────────────────────────────────────────

pub fn load(path: &str) -> i32 {
    let path = PathBuf::from(path);

    if !path.exists() {
        eprintln!("{RED}✗{NC} File not found: {}", path.display());
        return 1;
    }

    if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
        eprintln!("{YELLOW}⚠{NC} Warning: file does not have .wasm extension");
    }

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{RED}✗{NC} Failed to read {}: {}", path.display(), e);
            return 1;
        }
    };

    let registry = match PolicyModuleRegistry::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{RED}✗{NC} Failed to initialize WASM runtime: {}", e);
            return 1;
        }
    };

    match registry.load(&bytes) {
        Ok(meta) => {
            print_module_loaded(&path, &meta);

            // Copy to policy directory for auto-discovery on future startups
            let policy_dir = default_policy_dir();
            if let Err(e) = std::fs::create_dir_all(&policy_dir) {
                eprintln!(
                    "{YELLOW}⚠{NC} Could not create policy directory {}: {}",
                    policy_dir.display(),
                    e
                );
            } else {
                let dest = policy_dir.join(path.file_name().unwrap_or_default());
                if dest != path {
                    match std::fs::copy(&path, &dest) {
                        Ok(_) => {
                            eprintln!(
                                "  {DIM}Installed to {}{NC}",
                                dest.display()
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "{YELLOW}⚠{NC} Could not install to {}: {}",
                                dest.display(),
                                e
                            );
                        }
                    }
                }
            }
            0
        }
        Err(e) => {
            eprintln!("{RED}✗{NC} Failed to load WASM module: {}", e);
            eprintln!();
            eprintln!("  The module must export these functions:");
            eprintln!("    name_ptr() -> i32");
            eprintln!("    name_len() -> i32");
            eprintln!("    alloc(i32) -> i32");
            eprintln!("    evaluate(i32, i32) -> i32");
            eprintln!("    evaluate_len() -> i32");
            eprintln!("    memory (exported linear memory)");
            1
        }
    }
}

fn print_module_loaded(path: &std::path::Path, meta: &WasmModuleMetadata) {
    eprintln!();
    eprintln!("  {GREEN}✓{NC} Policy module loaded");
    eprintln!();
    eprintln!("  {BOLD}Name:{NC}    {CYAN}{}{NC}", meta.name);
    eprintln!(
        "  {BOLD}Hash:{NC}    {}",
        &meta.content_hash[..16]
    );
    eprintln!("  {BOLD}Size:{NC}    {} bytes", meta.size_bytes);
    eprintln!("  {BOLD}Source:{NC}  {}", path.display());
    eprintln!();
}

// ────────────────────────────────────────────────────────────────
// Subcommand: zp policy list
// ────────────────────────────────────────────────────────────────

pub fn list() -> i32 {
    let policy_dir = default_policy_dir();

    eprintln!();
    eprintln!("  {BOLD}Policy Modules{NC}");
    eprintln!("  {DIM}Directory: {}{NC}", policy_dir.display());
    eprintln!();

    if !policy_dir.exists() {
        eprintln!("  {DIM}No policy directory found.{NC}");
        eprintln!("  {DIM}Create ~/.zeropoint/policies/ and add .wasm files,{NC}");
        eprintln!("  {DIM}or use: zp policy load <file.wasm>{NC}");
        eprintln!();
        return 0;
    }

    let registry = match PolicyModuleRegistry::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{RED}✗{NC} Failed to initialize WASM runtime: {}", e);
            return 1;
        }
    };

    // Auto-discover from directory
    let results = registry.load_directory(&policy_dir);

    if results.is_empty() {
        eprintln!("  {DIM}No .wasm files found in {}{NC}", policy_dir.display());
        eprintln!("  {DIM}Use: zp policy load <file.wasm>{NC}");
        eprintln!();
        return 0;
    }

    let mut loaded = 0;
    let mut failed = 0;

    for result in &results {
        match result {
            Ok((path, meta)) => {
                loaded += 1;
                let filename = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                eprintln!(
                    "  {GREEN}●{NC} {CYAN}{}{NC}  {DIM}({}){NC}",
                    meta.name, filename
                );
                eprintln!(
                    "    Hash: {}  Size: {} bytes",
                    &meta.content_hash[..16],
                    meta.size_bytes
                );
            }
            Err((path, err)) => {
                failed += 1;
                let filename = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                eprintln!("  {RED}✗{NC} {filename}  {RED}{err}{NC}");
            }
        }
    }

    eprintln!();
    eprintln!(
        "  {DIM}{} module(s) loaded, {} failed{NC}",
        loaded, failed
    );
    eprintln!();
    0
}

// ────────────────────────────────────────────────────────────────
// Subcommand: zp policy status
// ────────────────────────────────────────────────────────────────

pub fn status() -> i32 {
    let policy_dir = default_policy_dir();

    eprintln!();
    eprintln!("  {BOLD}Policy Engine Status{NC}");
    eprintln!();

    // Report constitutional rules (always present)
    eprintln!("  {BOLD}Constitutional Rules{NC} {DIM}(hardcoded, non-removable){NC}");
    eprintln!("  {GREEN}●{NC} HarmPrincipleRule     {DIM}— Tenet I: Do No Harm{NC}");
    eprintln!("  {GREEN}●{NC} SovereigntyRule       {DIM}— Tenet II: Sovereignty Is Sacred{NC}");
    eprintln!();

    // Report operational rules (always present in default engine)
    eprintln!("  {BOLD}Operational Rules{NC} {DIM}(built-in){NC}");
    eprintln!("  {GREEN}●{NC} CatastrophicActionRule  {DIM}— blocks credential exfil, self-modification{NC}");
    eprintln!("  {GREEN}●{NC} BulkOperationRule       {DIM}— warns on glob/recursive file ops{NC}");
    eprintln!("  {GREEN}●{NC} ReputationGateRule      {DIM}— gates mesh actions by peer reputation{NC}");
    eprintln!();

    // Report baseline
    eprintln!("  {BOLD}Baseline{NC}");
    eprintln!("  {GREEN}●{NC} DefaultAllowRule        {DIM}— permits actions no rule restricts{NC}");
    eprintln!();

    // Report WASM modules
    eprintln!("  {BOLD}WASM Policy Modules{NC} {DIM}(~/.zeropoint/policies/){NC}");

    if !policy_dir.exists() {
        eprintln!("  {DIM}No policy directory configured{NC}");
        eprintln!();
        print_status_summary(6, 0, 0);
        return 0;
    }

    let registry = match PolicyModuleRegistry::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  {RED}✗{NC} WASM runtime unavailable: {}", e);
            eprintln!();
            print_status_summary(6, 0, 0);
            return 0;
        }
    };

    let results = registry.load_directory(&policy_dir);

    let mut wasm_loaded = 0;
    let mut wasm_failed = 0;

    if results.is_empty() {
        eprintln!("  {DIM}No modules installed{NC}");
    } else {
        for result in &results {
            match result {
                Ok((_path, meta)) => {
                    wasm_loaded += 1;
                    eprintln!(
                        "  {GREEN}●{NC} {}  {DIM}({}…){NC}",
                        meta.name,
                        &meta.content_hash[..8]
                    );
                }
                Err((path, err)) => {
                    wasm_failed += 1;
                    let filename = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");
                    eprintln!("  {RED}✗{NC} {filename}  {DIM}{err}{NC}");
                }
            }
        }
    }

    eprintln!();
    print_status_summary(6, wasm_loaded, wasm_failed);
    0
}

fn print_status_summary(native_rules: usize, wasm_loaded: usize, wasm_failed: usize) {
    let total = native_rules + wasm_loaded;
    eprintln!("  ──────────────────────────────────────────");
    eprintln!(
        "  {BOLD}Total:{NC} {} active rules ({} native + {} WASM)",
        total, native_rules, wasm_loaded
    );
    if wasm_failed > 0 {
        eprintln!(
            "  {YELLOW}⚠{NC} {} WASM module(s) failed to load",
            wasm_failed
        );
    }
    eprintln!(
        "  {DIM}Evaluation: Constitutional → Operational → WASM → Baseline{NC}"
    );
    eprintln!(
        "  {DIM}Guarantee: most restrictive decision wins (Block > Review > Warn > Sanitize > Allow){NC}"
    );
    eprintln!();
}

// ────────────────────────────────────────────────────────────────
// Subcommand: zp policy verify
// ────────────────────────────────────────────────────────────────

pub fn verify() -> i32 {
    let policy_dir = default_policy_dir();

    eprintln!();
    eprintln!("  {BOLD}Policy Module Integrity Check{NC}");
    eprintln!();

    if !policy_dir.exists() {
        eprintln!("  {DIM}No policy directory found — nothing to verify.{NC}");
        eprintln!();
        return 0;
    }

    let registry = match PolicyModuleRegistry::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{RED}✗{NC} Failed to initialize WASM runtime: {}", e);
            return 1;
        }
    };

    let results = registry.load_directory(&policy_dir);

    if results.is_empty() {
        eprintln!("  {DIM}No .wasm files found.{NC}");
        eprintln!();
        return 0;
    }

    // Load succeeded — now verify integrity
    let integrity = registry.verify_integrity();
    let mut all_ok = true;

    for (hash, valid) in &integrity {
        if *valid {
            eprintln!(
                "  {GREEN}✓{NC} {}…  {DIM}integrity OK{NC}",
                &hash[..16]
            );
        } else {
            all_ok = false;
            eprintln!(
                "  {RED}✗{NC} {}…  {RED}INTEGRITY MISMATCH{NC}",
                &hash[..16]
            );
        }
    }

    eprintln!();

    if all_ok {
        eprintln!("  {GREEN}All modules passed integrity verification.{NC}");
        eprintln!();
        0
    } else {
        eprintln!("  {RED}Some modules failed integrity checks!{NC}");
        eprintln!("  {DIM}This may indicate corruption. Re-install affected modules.{NC}");
        eprintln!();
        1
    }
}

// ────────────────────────────────────────────────────────────────
// Subcommand: zp policy remove <hash_prefix>
// ────────────────────────────────────────────────────────────────

pub fn remove(hash_prefix: &str) -> i32 {
    let policy_dir = default_policy_dir();

    if !policy_dir.exists() {
        eprintln!("{RED}✗{NC} No policy directory found.");
        return 1;
    }

    // Find .wasm files and match by hash prefix
    let registry = match PolicyModuleRegistry::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{RED}✗{NC} Failed to initialize WASM runtime: {}", e);
            return 1;
        }
    };

    let results = registry.load_directory(&policy_dir);

    let mut matched: Vec<(PathBuf, WasmModuleMetadata)> = Vec::new();

    for (path, meta) in results.into_iter().flatten() {
        if meta.content_hash.starts_with(hash_prefix) || meta.name == hash_prefix {
            matched.push((path, meta));
        }
    }

    if matched.is_empty() {
        eprintln!("{RED}✗{NC} No module matching '{}' found.", hash_prefix);
        eprintln!("  {DIM}Use `zp policy list` to see installed modules.{NC}");
        return 1;
    }

    if matched.len() > 1 {
        eprintln!(
            "{YELLOW}⚠{NC} Ambiguous prefix '{}' matches {} modules:",
            hash_prefix,
            matched.len()
        );
        for (_, meta) in &matched {
            eprintln!(
                "    {} ({}…)",
                meta.name,
                &meta.content_hash[..16]
            );
        }
        eprintln!("  Provide a longer prefix to disambiguate.");
        return 1;
    }

    let (path, meta) = &matched[0];

    match std::fs::remove_file(path) {
        Ok(_) => {
            eprintln!();
            eprintln!(
                "  {GREEN}✓{NC} Removed module '{CYAN}{}{NC}' ({}…)",
                meta.name,
                &meta.content_hash[..16]
            );
            eprintln!("  {DIM}File: {}{NC}", path.display());
            eprintln!();
            0
        }
        Err(e) => {
            eprintln!(
                "{RED}✗{NC} Failed to remove {}: {}",
                path.display(),
                e
            );
            1
        }
    }
}
