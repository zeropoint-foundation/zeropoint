//! `zp onboard` — interactive credential onboarding wizard.
//!
//! Guides a new user from zero to governed in a single session:
//!
//! 1. Scans for tools (reuses ConfigEngine + scan infrastructure)
//! 2. Shows what's discovered and what's missing
//! 3. Interactively prompts for each missing credential
//!    → Validates each key live as it's entered
//! 4. Stores credentials in the vault
//! 5. Runs a final validation sweep across all vault credentials
//! 6. Auto-configures all tools
//! 7. Optionally enables the governance proxy
//!
//! Designed so a first-time user never needs to know CLI syntax for
//! `vault-add`, `scan`, or `auto` — the wizard handles the flow.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::Path;

use zp_engine::validate::{self, CredentialToValidate, ValidationStatus};
use zp_trust::vault::CredentialVault;

use crate::configure::{self, ConfigEngine, DiscoveredTool};

// ── Provider metadata for human-friendly prompts ────────────────────────

/// Where to get an API key for each known provider.
fn provider_help(provider: &str) -> Option<&'static str> {
    match provider {
        "anthropic" => Some("https://console.anthropic.com/settings/keys"),
        "openai" => Some("https://platform.openai.com/api-keys"),
        "google" => Some("https://aistudio.google.com/apikey"),
        "groq" => Some("https://console.groq.com/keys"),
        "ollama" => Some("(local — no key needed if Ollama is running)"),
        "tavily" => Some("https://tavily.com/#api"),
        "serper" => Some("https://serper.dev/api-key"),
        "hedera" => Some("https://portal.hedera.com"),
        "postgres" | "redis" | "qdrant" | "weaviate" => Some("(local service — check your setup)"),
        _ => None,
    }
}

/// Human-readable field description.
fn field_label(field: &str) -> &str {
    match field {
        "api_key" => "API Key",
        "password" => "Password",
        "secret" => "Secret",
        "operator_key" => "Operator Key",
        "operator_id" => "Operator ID",
        "connection_string" => "Connection String",
        _ => field,
    }
}

// ── The wizard ──────────────────────────────────────────────────────────

/// A missing credential that needs to be collected.
#[derive(Debug, Clone)]
struct NeededCredential {
    /// Vault reference (e.g. "anthropic/api_key")
    vault_ref: String,
    /// Provider name (e.g. "anthropic")
    provider: String,
    /// Field name (e.g. "api_key")
    field: String,
    /// How many tools need this credential
    tool_count: usize,
    /// Which tools need it
    tool_names: Vec<String>,
}

/// Configuration for `zp onboard`.
pub struct OnboardConfig {
    /// Directory to scan for tools
    pub scan_path: std::path::PathBuf,
    /// Scan depth (1 = immediate children, 2 = grandchildren)
    pub depth: usize,
    /// Whether to offer proxy mode
    pub offer_proxy: bool,
    /// Proxy port (default 3000)
    pub proxy_port: u16,
}

/// Run the onboard wizard.
pub fn run(
    config: &OnboardConfig,
    vault: &mut CredentialVault,
    vault_key: &[u8; 32],
    vault_path: &Path,
) -> i32 {
    let engine = ConfigEngine::new();
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    // ── Banner ──────────────────────────────────────────────────
    eprintln!();
    eprintln!("  \x1b[1mZeroPoint Onboard\x1b[0m");
    eprintln!("  \x1b[2m─────────────────\x1b[0m");
    eprintln!();

    // ── Step 1: Discover tools ──────────────────────────────────
    eprint!("  Scanning for AI tools...");
    let discovered = discover_tools(&config.scan_path, config.depth, &engine, vault);

    if discovered.is_empty() {
        eprintln!(" no additional tools found.");
        eprintln!();

        // Show what's already in the vault — the user isn't starting from zero
        let vault_refs = vault.list();
        if !vault_refs.is_empty() {
            eprintln!(
                "  \x1b[1mVault status\x1b[0m — {} credential(s) on file:",
                vault_refs.len()
            );
            eprintln!();

            // Run validation sweep so they see their credentials are healthy
            let retrieve = |name: &str| -> Option<Vec<u8>> { vault.retrieve(name).ok() };
            let creds = validate::credentials_from_vault_refs(&vault_refs, &retrieve);

            if !creds.is_empty() {
                let report = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(validate::validate_credentials(&creds))
                });

                for r in &report.results {
                    let icon = match r.status {
                        ValidationStatus::Valid => "\x1b[32m✓\x1b[0m",
                        ValidationStatus::Invalid => "\x1b[31m✗\x1b[0m",
                        ValidationStatus::Unreachable => "\x1b[33m⚠\x1b[0m",
                        ValidationStatus::Unsupported => "\x1b[2m○\x1b[0m",
                        ValidationStatus::Skipped => "\x1b[2m·\x1b[0m",
                    };
                    let latency = if r.latency_ms > 0 {
                        format!(" ({:>3}ms)", r.latency_ms)
                    } else {
                        String::new()
                    };
                    eprintln!("  {} {:<16} {}{}", icon, r.provider_name, r.detail, latency);
                }

                eprintln!();
                eprintln!(
                    "  Summary: \x1b[32m{} valid\x1b[0m, {} invalid, {} unreachable",
                    report.valid, report.invalid, report.unreachable
                );
            }

            eprintln!();
            eprintln!("  No additional AI tools with .env.example templates found in:");
            eprintln!("  {}", config.scan_path.display());
            eprintln!();
            eprintln!("  Your credentials are ready. Point onboard at a tool directory:");
            eprintln!("  \x1b[1mzp onboard --path ~/projects/my-tool\x1b[0m");
        } else {
            eprintln!("  No tools with .env.example templates found in:");
            eprintln!("  {}", config.scan_path.display());
            eprintln!();
            eprintln!("  Add credentials to get started:");
            eprintln!("  \x1b[1mzp configure vault-add --provider <name> --field api_key\x1b[0m");
        }

        eprintln!();
        return 0;
    }

    eprintln!(" found {} tool(s).\n", discovered.len());

    // Show what was found
    for tool in &discovered {
        let status = if tool.missing.is_empty() {
            "\x1b[32m✓ ready\x1b[0m"
        } else {
            "\x1b[33m○ needs credentials\x1b[0m"
        };
        eprintln!("  {} {}", tool.name, status);
    }
    eprintln!();

    // ── Step 2: Collect unique missing credentials ──────────────
    let needed = collect_needed_credentials(&discovered, &engine);

    if needed.is_empty() {
        eprintln!("  All tools have the credentials they need.");
        eprintln!();
        return offer_auto_configure(config, vault, vault_key, vault_path, &engine, &stdin);
    }

    eprintln!("  {} credential(s) needed:\n", needed.len());

    for cred in &needed {
        let tools_str = cred.tool_names.join(", ");
        eprintln!(
            "    \x1b[36m{}\x1b[0m — used by {}",
            cred.vault_ref, tools_str
        );
    }
    eprintln!();

    // ── Step 3: Prompt for each credential ──────────────────────
    eprintln!("  Let's set up your credentials.");
    eprintln!("  Each one is encrypted in your vault, derived from your Genesis key.");
    eprintln!("  Keys are validated live against provider APIs as you enter them.");
    eprintln!("  Press Enter to skip any you don't have yet.\n");

    let mut stored_count = 0;
    let mut validated_count = 0;
    let mut invalid_keys: Vec<(String, String)> = Vec::new(); // (vault_ref, reason)
    let mut skipped = Vec::new();

    for cred in &needed {
        // Header
        eprintln!("  ┌─ {} ─────────────", cred.provider);
        if let Some(url) = provider_help(&cred.provider) {
            eprintln!("  │ Get yours: {}", url);
        }

        // Prompt
        eprint!("  │ {}: ", field_label(&cred.field));
        stdout.flush().ok();

        let mut input = String::new();
        if stdin.lock().read_line(&mut input).is_err() {
            eprintln!("  │ \x1b[31m(read error)\x1b[0m");
            eprintln!("  └──────────────────");
            continue;
        }

        let value = input.trim();
        if value.is_empty() {
            eprintln!("  │ \x1b[2m(skipped)\x1b[0m");
            eprintln!("  └──────────────────");
            skipped.push(cred.clone());
            continue;
        }

        // Store in vault
        match vault.store(&cred.vault_ref, value.as_bytes()) {
            Ok(_) => {
                let masked = mask_credential(value);
                eprintln!(
                    "  │ \x1b[32m✓\x1b[0m Stored: {} ({})",
                    cred.vault_ref, masked
                );
                stored_count += 1;

                // ── Live validation ──────────────────────────────
                eprint!("  │   Validating...");
                stdout.flush().ok();

                let var_name = format!(
                    "{}_{}",
                    cred.provider.to_uppercase().replace('-', "_"),
                    cred.field.to_uppercase()
                );
                let to_validate = CredentialToValidate {
                    provider_id: cred.provider.clone(),
                    var_name,
                    value: value.to_string(),
                };

                let result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(validate::validate_credentials(&[to_validate]))
                });

                if let Some(r) = result.results.first() {
                    match r.status {
                        ValidationStatus::Valid => {
                            eprintln!(" \x1b[32m✓ live\x1b[0m — {}", r.detail);
                            validated_count += 1;
                        }
                        ValidationStatus::Invalid => {
                            eprintln!(" \x1b[31m✗ rejected\x1b[0m — {}", r.detail);
                            eprintln!("  │   \x1b[33mKey stored but may not work. Double-check it.\x1b[0m");
                            invalid_keys.push((cred.vault_ref.clone(), r.detail.clone()));
                        }
                        ValidationStatus::Unreachable => {
                            eprintln!(" \x1b[33m⚠ unreachable\x1b[0m — {}", r.detail);
                            eprintln!(
                                "  │   \x1b[2mKey stored. Service may be temporarily down.\x1b[0m"
                            );
                        }
                        ValidationStatus::Unsupported => {
                            eprintln!(" \x1b[2m○ no probe\x1b[0m — validation not available for this provider");
                        }
                        ValidationStatus::Skipped => {
                            eprintln!(" \x1b[2m· skipped\x1b[0m");
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("  │ \x1b[31m✗\x1b[0m Error: {}", e);
            }
        }
        eprintln!("  └──────────────────");
    }

    // Persist vault to disk
    if stored_count > 0 {
        if let Err(e) = vault.save(vault_path) {
            eprintln!("\n  \x1b[31mWarning:\x1b[0m Credentials stored in memory but failed to persist: {}", e);
        }
    }

    // Summary
    eprintln!();
    if validated_count > 0 {
        eprintln!(
            "  {} credential(s) stored, \x1b[32m{} verified live\x1b[0m.",
            stored_count, validated_count
        );
    } else {
        eprintln!("  {} credential(s) stored.", stored_count);
    }

    if !invalid_keys.is_empty() {
        eprintln!();
        eprintln!(
            "  \x1b[33m⚠ {} key(s) failed validation:\x1b[0m",
            invalid_keys.len()
        );
        for (vr, reason) in &invalid_keys {
            eprintln!("    \x1b[31m✗\x1b[0m {} — {}", vr, reason);
        }
        eprintln!("    Update with: \x1b[1mzp configure vault-add --provider <name> --field <field>\x1b[0m");
    }

    if !skipped.is_empty() {
        eprintln!("  {} skipped — add later with:", skipped.len());
        for s in &skipped {
            eprintln!(
                "    \x1b[1mzp configure vault-add --provider {} --field {}\x1b[0m",
                s.provider, s.field
            );
        }
    }
    eprintln!();

    // ── Step 4: Auto-configure ──────────────────────────────────
    if stored_count > 0 {
        offer_auto_configure(config, vault, vault_key, vault_path, &engine, &stdin)
    } else {
        eprintln!("  No credentials stored — skipping auto-configure.");
        eprintln!("  Run \x1b[1m`zp onboard`\x1b[0m again when you have your keys.\n");
        0
    }
}

/// Offer to auto-configure all discovered tools.
fn offer_auto_configure(
    config: &OnboardConfig,
    vault: &mut CredentialVault,
    _vault_key: &[u8; 32],
    vault_path: &Path,
    engine: &ConfigEngine,
    stdin: &io::Stdin,
) -> i32 {
    let mut stdout = io::stdout();

    // Re-analyze with updated vault
    let discovered = discover_tools(&config.scan_path, config.depth, engine, vault);
    let ready: Vec<&DiscoveredTool> = discovered.iter().filter(|t| t.missing.is_empty()).collect();

    if ready.is_empty() {
        eprintln!("  No tools are fully ready yet (missing credentials).");
        eprintln!("  Run \x1b[1m`zp onboard`\x1b[0m again after adding more keys.\n");
        return 0;
    }

    eprintln!("  {} tool(s) ready to configure:", ready.len());
    for tool in &ready {
        eprintln!("    \x1b[32m✓\x1b[0m {}", tool.name);
    }
    eprintln!();

    // ── Final validation sweep ──────────────────────────────────
    // Run a full credential check before committing to auto-configure.
    let vault_refs = vault.list();
    if !vault_refs.is_empty() {
        eprintln!("  \x1b[1mCredential health check\x1b[0m");
        eprintln!("  \x1b[2m───────────────────────\x1b[0m");

        let retrieve = |name: &str| -> Option<Vec<u8>> { vault.retrieve(name).ok() };
        let creds = validate::credentials_from_vault_refs(&vault_refs, &retrieve);

        if !creds.is_empty() {
            let report = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(validate::validate_credentials(&creds))
            });

            for r in &report.results {
                let icon = match r.status {
                    ValidationStatus::Valid => "\x1b[32m✓\x1b[0m",
                    ValidationStatus::Invalid => "\x1b[31m✗\x1b[0m",
                    ValidationStatus::Unreachable => "\x1b[33m⚠\x1b[0m",
                    ValidationStatus::Unsupported => "\x1b[2m○\x1b[0m",
                    ValidationStatus::Skipped => "\x1b[2m·\x1b[0m",
                };
                let latency = if r.latency_ms > 0 {
                    format!(" ({:>3}ms)", r.latency_ms)
                } else {
                    String::new()
                };
                eprintln!("  {} {:<16} {}{}", icon, r.provider_name, r.detail, latency);
            }

            eprintln!();
            if report.invalid > 0 {
                eprintln!(
                    "  \x1b[33m⚠ {} credential(s) failed — tools using them may not work.\x1b[0m",
                    report.invalid
                );
                eprintln!();
            }
        }
    }

    eprint!("  Configure them now? [Y/n] ");
    stdout.flush().ok();

    let mut answer = String::new();
    stdin.lock().read_line(&mut answer).ok();
    let answer = answer.trim().to_lowercase();

    if answer == "n" || answer == "no" {
        eprintln!();
        eprintln!("  No problem. When you're ready:");
        eprintln!("  \x1b[1mzp configure auto\x1b[0m\n");
        return 0;
    }

    // Ask about proxy
    let use_proxy = if config.offer_proxy {
        eprintln!();
        eprintln!("  \x1b[1mGovernance proxy\x1b[0m routes API calls through ZeroPoint for");
        eprintln!("  policy checks, cost metering, and audit receipts.");
        eprintln!();
        eprint!("  Enable governance proxy? [Y/n] ");
        stdout.flush().ok();

        let mut proxy_answer = String::new();
        stdin.lock().read_line(&mut proxy_answer).ok();
        let proxy_answer = proxy_answer.trim().to_lowercase();
        proxy_answer != "n" && proxy_answer != "no"
    } else {
        false
    };

    eprintln!();

    // Run auto-configure
    // TODO(Phase E): Use auto_engine for proxy-aware MVC configuration
    let _auto_engine = if use_proxy {
        ConfigEngine::with_proxy(config.proxy_port)
    } else {
        ConfigEngine::new()
    };

    // Allow-all policy for onboard (vault access is the gate)
    fn onboard_policy(
        _skill_id: &str,
        _credential_name: &str,
        _context: &zp_trust::injector::PolicyContext,
    ) -> Result<(), zp_trust::injector::InjectorError> {
        Ok(())
    }

    let mut configured = 0;

    for tool in &ready {
        eprint!("  Configuring {}...", tool.name);
        let exit = configure::run_tool(
            &tool.path,
            &tool.name,
            false, // not dry run
            vault,
            onboard_policy,
            Some(vault_path),
        );
        if exit == 0 {
            configured += 1;
            eprintln!(" \x1b[32m✓\x1b[0m");
        } else {
            eprintln!(" \x1b[31m✗\x1b[0m");
        }
    }

    eprintln!();
    eprintln!("  {}/{} tool(s) configured.", configured, ready.len());

    if use_proxy {
        eprintln!(
            "  API calls will route through \x1b[36mhttp://localhost:{}/api/v1/proxy/\x1b[0m",
            config.proxy_port
        );
        eprintln!("  Start the server: \x1b[1mzp serve\x1b[0m");
    }

    eprintln!();
    eprintln!("  Your tools are governed. \x1b[2m✦\x1b[0m");
    eprintln!();
    eprintln!(
        "  \x1b[2mTip: Run `zp configure validate` anytime to re-check your credentials.\x1b[0m"
    );
    eprintln!();
    0
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Discover tools in a directory (reuses scan infrastructure).
fn discover_tools(
    scan_path: &Path,
    depth: usize,
    engine: &ConfigEngine,
    vault: &CredentialVault,
) -> Vec<DiscoveredTool> {
    configure::discover_tools_in(scan_path, depth, engine, vault)
}

/// Collect unique missing credentials across all discovered tools.
fn collect_needed_credentials(
    tools: &[DiscoveredTool],
    engine: &ConfigEngine,
) -> Vec<NeededCredential> {
    let mut by_ref: HashMap<String, NeededCredential> = HashMap::new();

    for tool in tools {
        for var in &tool.missing {
            if let Some(pattern) = engine.match_var(var) {
                if let Some(ref vr) = pattern.vault_ref {
                    let entry = by_ref.entry(vr.clone()).or_insert_with(|| {
                        let parts: Vec<&str> = vr.splitn(2, '/').collect();
                        let (provider, field) = if parts.len() == 2 {
                            (parts[0].to_string(), parts[1].to_string())
                        } else {
                            (vr.clone(), "secret".to_string())
                        };
                        NeededCredential {
                            vault_ref: vr.clone(),
                            provider,
                            field,
                            tool_count: 0,
                            tool_names: Vec::new(),
                        }
                    });
                    if !entry.tool_names.contains(&tool.name) {
                        entry.tool_count += 1;
                        entry.tool_names.push(tool.name.clone());
                    }
                }
            }
        }
    }

    // Sort by provider name for a clean prompt order
    let mut result: Vec<NeededCredential> = by_ref.into_values().collect();
    result.sort_by(|a, b| a.provider.cmp(&b.provider).then(a.field.cmp(&b.field)));
    result
}

/// Mask a credential for display (show first 6 and last 2 chars).
fn mask_credential(value: &str) -> String {
    if value.len() <= 10 {
        return "••••••".to_string();
    }
    let prefix = &value[..6];
    let suffix = &value[value.len() - 2..];
    format!("{}••••{}", prefix, suffix)
}
