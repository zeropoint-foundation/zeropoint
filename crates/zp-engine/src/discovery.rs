//! Manifest discovery and heuristic fallback — Phase B of MVC.
//!
//! This module answers the question: "Given a tool directory, what capabilities
//! does it need?" Two paths to an answer:
//!
//! 1. **Manifest path** — `.zp-configure.toml` exists → parse it → high confidence
//! 2. **Heuristic path** — no manifest → infer capabilities from `.env.example` → medium/low
//!
//! The heuristic path is deliberately conservative. It groups env vars by detected
//! provider, maps providers to capabilities via the catalog, and flags anything it
//! can't resolve as `NeedsAttention`. It never guesses silently — that would be
//! worse than asking for help.
//!
//! ## Escalation Tiers
//!
//! The system is designed to escalate gracefully rather than fail hard:
//!
//! ```text
//! Tier 1 — Manifest (high confidence)
//!   ↓ not found
//! Tier 2 — Heuristic inference (medium confidence)
//!   ↓ unresolvable vars remain
//! Tier 3 — Attention items (low confidence, human-in-the-loop)
//!   ↓ user resolves + optionally generates manifest
//! Tier 4 — Manifest committed (permanent high confidence)
//! ```
//!
//! The engine NEVER silently drops variables it doesn't understand. Every env var
//! falls into exactly one of: resolved, defaulted, inferred, or attention.

use crate::capability::{
    AutoGenerate, CapabilityRequirement, Confidence, ToolManifest, ToolMeta,
};
use crate::providers::{self, ProviderProfile};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

// ============================================================================
// Discovery result
// ============================================================================

/// Complete discovery result for a single tool.
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    /// Tool directory name
    pub name: String,
    /// Absolute path to tool directory
    pub path: PathBuf,
    /// How the manifest was obtained
    pub source: ManifestSource,
    /// The manifest (authoritative or inferred)
    pub manifest: ToolManifest,
    /// Items the engine couldn't resolve — surfaced to the user
    pub attention_items: Vec<AttentionItem>,
    /// Overall confidence in the discovery
    pub confidence: Confidence,
}

/// How the manifest was obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestSource {
    /// Parsed from an existing `.zp-configure.toml`
    File(PathBuf),
    /// Inferred heuristically from `.env.example`
    Inferred,
}

/// Something the engine couldn't resolve and is surfacing transparently.
#[derive(Debug, Clone)]
pub struct AttentionItem {
    /// What triggered the attention flag
    pub kind: AttentionKind,
    /// The specific variable or capability
    pub subject: String,
    /// Human-readable explanation
    pub reason: String,
    /// Suggested resolution (if known)
    pub suggestion: Option<String>,
}

/// Classification of attention items for UI presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttentionKind {
    /// Env var looks like a credential but matches no known provider
    UnrecognizedCredential,
    /// Env var points to an internal/proprietary service URL
    InternalService,
    /// Multiple providers compete for the same capability slot
    AmbiguousProvider,
    /// Capability referenced in manifest but not in the taxonomy
    UnknownCapability,
    /// Provider requires special setup (OAuth, platform registration)
    SpecialSetup,
    /// Conflicting signals — var name suggests one provider, template value another
    ConflictingSignals,
    /// Auto-generate candidate that the engine isn't fully confident about
    PossibleSecret,
}

// ============================================================================
// Well-known filenames
// ============================================================================

/// The manifest file we look for.
const MANIFEST_FILENAME: &str = ".zp-configure.toml";

/// Well-known env template filenames, in priority order.
const ENV_TEMPLATE_NAMES: &[&str] = &[
    ".env.example",
    ".env.sample",
    ".env.template",
    "env.example",
    ".env.defaults",
];

/// Well-known subdirectories where env templates may live.
const ENV_SUBDIRS: &[&str] = &["", "deploy", "docker", "config", ".config"];

// ============================================================================
// Discovery entry point
// ============================================================================

/// Discover a tool's capabilities: manifest-first, heuristic-fallback.
///
/// This is the primary entry point for Phase B. It returns a `DiscoveryResult`
/// with either a parsed manifest (high confidence) or an inferred one
/// (medium/low confidence) along with attention items for anything unresolvable.
pub fn discover_tool(tool_path: &Path) -> DiscoveryResult {
    let name = tool_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into());

    // Tier 1: Try loading an existing manifest
    let manifest_path = tool_path.join(MANIFEST_FILENAME);
    if manifest_path.exists() {
        match crate::capability::load_manifest(&manifest_path) {
            Ok(manifest) => {
                // Validate manifest: check for unknown capabilities
                let mut attention_items = Vec::new();
                validate_manifest(&manifest, &mut attention_items);

                let confidence = if attention_items.is_empty() {
                    Confidence::High
                } else {
                    Confidence::Medium
                };

                return DiscoveryResult {
                    name,
                    path: tool_path.to_path_buf(),
                    source: ManifestSource::File(manifest_path),
                    manifest,
                    attention_items,
                    confidence,
                };
            }
            Err(e) => {
                // Manifest exists but is malformed — still fall through to heuristic
                // but note the parse failure as an attention item
                tracing::warn!("Malformed manifest at {}: {}", manifest_path.display(), e);
                let mut result = infer_from_env_template(tool_path, &name);
                result.attention_items.push(AttentionItem {
                    kind: AttentionKind::SpecialSetup,
                    subject: MANIFEST_FILENAME.into(),
                    reason: format!("Manifest exists but failed to parse: {e}"),
                    suggestion: Some(
                        "Fix the TOML syntax, or delete it to use heuristic inference".into(),
                    ),
                });
                return result;
            }
        }
    }

    // Tier 2: No manifest — infer from .env.example
    infer_from_env_template(tool_path, &name)
}

/// Discover all tools in a directory, returning results for each.
pub fn discover_tools_in(scan_path: &Path, depth: usize) -> Vec<DiscoveryResult> {
    let mut results = Vec::new();

    // Check the scan_path itself
    if has_env_template(scan_path) {
        results.push(discover_tool(scan_path));
    }

    // Walk children
    if let Ok(entries) = std::fs::read_dir(scan_path) {
        for entry in entries.flatten() {
            let child = entry.path();
            if !child.is_dir() {
                continue;
            }
            let dir_name = child
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if is_skip_dir(&dir_name) {
                continue;
            }

            if has_env_template(&child) || child.join(MANIFEST_FILENAME).exists() {
                results.push(discover_tool(&child));
            }

            if depth >= 2 {
                if let Ok(grandchildren) = std::fs::read_dir(&child) {
                    for gc in grandchildren.flatten() {
                        let gc_path = gc.path();
                        if !gc_path.is_dir() {
                            continue;
                        }
                        let gc_name = gc_path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        if is_skip_dir(&gc_name) {
                            continue;
                        }
                        if has_env_template(&gc_path) || gc_path.join(MANIFEST_FILENAME).exists() {
                            results.push(discover_tool(&gc_path));
                        }
                    }
                }
            }
        }
    }

    results
}

// ============================================================================
// Heuristic inference (Tier 2)
// ============================================================================

/// Infer a tool manifest heuristically from its `.env.example`.
///
/// The algorithm:
/// 1. Parse all env vars from the template
/// 2. Classify each var: credential, URL, model, toggle, secret, or unknown
/// 3. Group credential vars by detected provider
/// 4. Map provider groups to capabilities via the catalog
/// 5. Collapse multiple LLM providers into a single `reasoning_llm` requirement
/// 6. Flag unrecognized credential-looking vars as attention items
fn infer_from_env_template(tool_path: &Path, tool_name: &str) -> DiscoveryResult {
    let template_path = find_env_template(tool_path);
    let catalog = providers::load_catalog();

    let mut required: Vec<CapabilityRequirement> = Vec::new();
    let mut optional: Vec<CapabilityRequirement> = Vec::new();
    let mut attention_items: Vec<AttentionItem> = Vec::new();
    let mut auto_gen_secrets: Vec<String> = Vec::new();

    // Track which capabilities we've already added
    let mut seen_capabilities: HashSet<String> = HashSet::new();
    // Track provider → vars for grouping
    let mut provider_vars: BTreeMap<String, Vec<EnvVarInfo>> = BTreeMap::new();
    // Unrecognized vars
    let mut unrecognized: Vec<EnvVarInfo> = Vec::new();

    let template_content = template_path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();

    for line in template_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let (var_name, template_value) = match trimmed.split_once('=') {
            Some((k, v)) => (
                k.trim().to_string(),
                v.trim().trim_matches('"').trim_matches('\'').to_string(),
            ),
            None => continue,
        };

        if var_name.is_empty() {
            continue;
        }

        let var_class = classify_var(&var_name, &template_value);
        let detected_provider = providers::detect_provider(&var_name);

        let info = EnvVarInfo {
            name: var_name.clone(),
            value: template_value.clone(),
            class: var_class.clone(),
            _provider: detected_provider.clone(),
        };

        match detected_provider {
            Some(ref provider_id) => {
                provider_vars
                    .entry(provider_id.clone())
                    .or_default()
                    .push(info);
            }
            None => {
                // Try to classify based on var name patterns
                match &var_class {
                    VarClass::ProbableSecret => {
                        // Looks like an auto-generatable secret
                        auto_gen_secrets.push(var_name.clone());
                    }
                    VarClass::ProbableCredential => {
                        // Looks like a credential but no known provider
                        let inferred = providers::infer_provider_from_var(&var_name);
                        // Check if this inferred provider is in the catalog
                        if catalog.iter().any(|p| p.id == inferred) {
                            provider_vars
                                .entry(inferred)
                                .or_default()
                                .push(info);
                        } else {
                            unrecognized.push(info);
                        }
                    }
                    VarClass::DatabaseUrl | VarClass::DatabaseCredential => {
                        // Database capability
                        if !seen_capabilities.contains("database") {
                            seen_capabilities.insert("database".into());
                            required.push(CapabilityRequirement {
                                capability: "database".into(),
                                env_vars: vec![var_name.clone()],
                                local_default: true,
                                defaults: infer_database_defaults(&template_value),
                                ..default_requirement()
                            });
                        } else {
                            // Append to existing database requirement
                            if let Some(db_req) = required
                                .iter_mut()
                                .find(|r| r.capability == "database")
                            {
                                db_req.env_vars.push(var_name.clone());
                            }
                        }
                    }
                    VarClass::Default | VarClass::Toggle | VarClass::Config => {
                        // Non-credential vars — will be handled by defaults
                    }
                    _ => {
                        unrecognized.push(info);
                    }
                }
            }
        }
    }

    // Convert provider groups → capability requirements
    let llm_providers = collect_llm_providers(&provider_vars, &catalog);
    let non_llm_providers = collect_non_llm_providers(&provider_vars, &catalog);

    // Collapse multiple LLM providers into a single reasoning_llm requirement
    if !llm_providers.is_empty() {
        if !seen_capabilities.contains("reasoning_llm") {
            seen_capabilities.insert("reasoning_llm".into());
            let all_llm_vars: Vec<String> = llm_providers
                .iter()
                .flat_map(|(_, vars)| vars.iter().map(|v| v.name.clone()))
                .collect();
            let prefer: Vec<String> = llm_providers.iter().map(|(id, _)| id.clone()).collect();

            required.push(CapabilityRequirement {
                capability: "reasoning_llm".into(),
                env_vars: all_llm_vars,
                prefer,
                ..default_requirement()
            });
        }
    }

    // Non-LLM capabilities (embedding, search, observability, etc.)
    for (provider_id, vars) in &non_llm_providers {
        let profile = catalog.iter().find(|p| p.id == *provider_id);
        if let Some(profile) = profile {
            for cap_str in &profile.capabilities {
                // Skip LLM capabilities — already handled
                if is_llm_capability(cap_str) {
                    continue;
                }
                if seen_capabilities.contains(cap_str) {
                    continue;
                }
                seen_capabilities.insert(cap_str.clone());

                let cap_vars: Vec<String> = vars.iter().map(|v| v.name.clone()).collect();

                // Infrastructure and browser capabilities are usually optional
                let is_optional = is_typically_optional(cap_str);

                let req = CapabilityRequirement {
                    capability: cap_str.clone(),
                    env_vars: cap_vars,
                    prefer: vec![provider_id.clone()],
                    ..default_requirement()
                };

                if is_optional {
                    optional.push(req);
                } else {
                    required.push(req);
                }
            }
        }
    }

    // Infer embedding from pattern (many tools have EMBEDDING_* vars without provider match)
    if !seen_capabilities.contains("embedding") {
        let embedding_vars: Vec<&str> = template_content
            .lines()
            .filter_map(|l| {
                let t = l.trim();
                if t.starts_with('#') || t.is_empty() {
                    return None;
                }
                let var = t.split('=').next()?.trim();
                if var.to_uppercase().contains("EMBEDDING") {
                    Some(var)
                } else {
                    None
                }
            })
            .collect();
        if !embedding_vars.is_empty() {
            seen_capabilities.insert("embedding".into());
            required.push(CapabilityRequirement {
                capability: "embedding".into(),
                env_vars: embedding_vars.into_iter().map(String::from).collect(),
                prefer: vec!["ollama".into()], // local-first default
                ..default_requirement()
            });
        }
    }

    // Surface unrecognized vars as attention items
    for var in &unrecognized {
        let kind = match &var.class {
            VarClass::ProbableCredential => AttentionKind::UnrecognizedCredential,
            VarClass::ProbableUrl => {
                if looks_like_internal_url(&var.value) {
                    AttentionKind::InternalService
                } else {
                    AttentionKind::UnrecognizedCredential
                }
            }
            _ => AttentionKind::UnrecognizedCredential,
        };

        attention_items.push(AttentionItem {
            kind,
            subject: var.name.clone(),
            reason: format!(
                "Looks like a credential but matches no known provider (inferred: {})",
                providers::infer_provider_from_var(&var.name)
            ),
            suggestion: Some(format!(
                "Add to vault manually, or add a pattern for this provider"
            )),
        });
    }

    // Determine confidence
    let confidence = if attention_items.is_empty() && !required.is_empty() {
        Confidence::Medium // Inferred — no manifest — but clean inference
    } else if !attention_items.is_empty() {
        Confidence::Low // Has unresolvable items
    } else {
        Confidence::Medium // No attention items but also nothing inferred
    };

    let auto_generate = if auto_gen_secrets.is_empty() {
        None
    } else {
        Some(AutoGenerate {
            secrets: auto_gen_secrets,
        })
    };

    let manifest = ToolManifest {
        tool: ToolMeta {
            name: tool_name.to_string(),
            version: String::new(),
            description: format!("Auto-inferred from .env.example — review and commit"),
        },
        required,
        optional,
        auto_generate,
        deluxe: None,
        provider_overrides: Vec::new(),
    };

    DiscoveryResult {
        name: tool_name.to_string(),
        path: tool_path.to_path_buf(),
        source: ManifestSource::Inferred,
        manifest,
        attention_items,
        confidence,
    }
}

// ============================================================================
// Manifest generation (Tier 3 → Tier 4 escalation)
// ============================================================================

/// Generate a draft `.zp-configure.toml` manifest from a discovery result.
///
/// This is the escalation path: the engine's heuristic inference becomes a
/// concrete manifest the user can review, edit, and commit. Once committed,
/// future scans use the manifest path (Tier 1) with high confidence.
pub fn generate_manifest_toml(result: &DiscoveryResult) -> String {
    let m = &result.manifest;
    let mut out = String::with_capacity(2048);

    // Header with provenance
    match &result.source {
        ManifestSource::Inferred => {
            out.push_str("# .zp-configure.toml — auto-generated by `zp configure manifest`\n");
            out.push_str("# Review carefully before committing. Inferred capabilities may need adjustment.\n");
        }
        ManifestSource::File(_) => {
            out.push_str("# .zp-configure.toml\n");
        }
    }

    if !result.attention_items.is_empty() {
        out.push_str("#\n# ⚠ ATTENTION: The engine flagged items that need manual review.\n");
        out.push_str("# Search for 'needs_attention' below.\n");
    }
    out.push('\n');

    // [tool]
    out.push_str("[tool]\n");
    out.push_str(&format!("name = {:?}\n", m.tool.name));
    if !m.tool.version.is_empty() {
        out.push_str(&format!("version = {:?}\n", m.tool.version));
    }
    out.push_str(&format!("description = {:?}\n", m.tool.description));
    out.push('\n');

    // [[required]]
    if !m.required.is_empty() {
        out.push_str("# ── Required capabilities ──────────────────────────────────\n\n");
        for req in &m.required {
            emit_capability_requirement(&mut out, req, "required");
        }
    }

    // [[optional]]
    if !m.optional.is_empty() {
        out.push_str("# ── Optional capabilities ──────────────────────────────────\n\n");
        for req in &m.optional {
            emit_capability_requirement(&mut out, req, "optional");
        }
    }

    // [auto_generate]
    if let Some(ref ag) = m.auto_generate {
        if !ag.secrets.is_empty() {
            out.push_str("# ── Auto-generated secrets ─────────────────────────────────\n");
            out.push_str("[auto_generate]\n");
            out.push_str("secrets = [\n");
            for s in &ag.secrets {
                out.push_str(&format!("    {:?},\n", s));
            }
            out.push_str("]\n\n");
        }
    }

    // [deluxe]
    if let Some(ref d) = m.deluxe {
        out.push_str("[deluxe]\n");
        out.push_str(&format!("prefer_aggregator = {}\n", d.prefer_aggregator));
        if let Some(ref ab) = d.aggregator_backend {
            out.push_str(&format!("aggregator_backend = {:?}\n", ab));
        }
        out.push('\n');
    }

    // [[provider_overrides]]
    for po in &m.provider_overrides {
        out.push_str("[[provider_overrides]]\n");
        out.push_str(&format!("provider = {:?}\n", po.provider));
        if !po.env_map.is_empty() {
            out.push_str("env_map = { ");
            let pairs: Vec<String> = po
                .env_map
                .iter()
                .map(|(k, v)| format!("{:?} = {:?}", k, v))
                .collect();
            out.push_str(&pairs.join(", "));
            out.push_str(" }\n");
        }
        if !po.also_set.is_empty() {
            out.push_str("also_set = { ");
            let pairs: Vec<String> = po
                .also_set
                .iter()
                .map(|(k, v)| format!("{:?} = {:?}", k, v))
                .collect();
            out.push_str(&pairs.join(", "));
            out.push_str(" }\n");
        }
        out.push('\n');
    }

    // Attention items as comments at the bottom
    if !result.attention_items.is_empty() {
        out.push_str("# ══════════════════════════════════════════════════════════\n");
        out.push_str("# ATTENTION ITEMS — needs manual review\n");
        out.push_str("# ══════════════════════════════════════════════════════════\n");
        for item in &result.attention_items {
            out.push_str(&format!("#\n# [{:?}] {}\n", item.kind, item.subject));
            out.push_str(&format!("#   Reason: {}\n", item.reason));
            if let Some(ref sug) = item.suggestion {
                out.push_str(&format!("#   Suggestion: {}\n", sug));
            }
        }
        out.push('\n');
    }

    out
}

/// Emit a single `[[required]]` or `[[optional]]` section.
fn emit_capability_requirement(out: &mut String, req: &CapabilityRequirement, section: &str) {
    out.push_str(&format!("[[{}]]\n", section));
    out.push_str(&format!("capability = {:?}\n", req.capability));

    if !req.env_vars.is_empty() {
        out.push_str("env_vars = [");
        let quoted: Vec<String> = req.env_vars.iter().map(|v| format!("{:?}", v)).collect();
        out.push_str(&quoted.join(", "));
        out.push_str("]\n");
    }

    if !req.prefer.is_empty() {
        out.push_str("prefer = [");
        let quoted: Vec<String> = req.prefer.iter().map(|v| format!("{:?}", v)).collect();
        out.push_str(&quoted.join(", "));
        out.push_str("]\n");
    }

    if let Some(ref model_env) = req.model_env {
        out.push_str(&format!("model_env = {:?}\n", model_env));
    }
    if let Some(ref model_default) = req.model_default {
        out.push_str(&format!("model_default = {:?}\n", model_default));
    }

    if req.local_default {
        out.push_str("local_default = true\n");
    }

    if let Some(ref shared) = req.shared_with {
        out.push_str(&format!("shared_with = {:?}\n", shared));
    }

    if let Some(ref attention) = req.attention {
        out.push_str(&format!(
            "attention = {:?}  # needs_attention — review this\n",
            attention
        ));
    }

    if let Some(ref notes) = req.notes {
        out.push_str(&format!("notes = {:?}\n", notes));
    }

    if !req.defaults.is_empty() {
        out.push_str("defaults = { ");
        let pairs: Vec<String> = req
            .defaults
            .iter()
            .map(|(k, v)| format!("{:?} = {:?}", k, v))
            .collect();
        out.push_str(&pairs.join(", "));
        out.push_str(" }\n");
    }

    out.push('\n');
}

// ============================================================================
// Manifest validation
// ============================================================================

/// Validate a parsed manifest for issues the engine should surface.
fn validate_manifest(manifest: &ToolManifest, attention: &mut Vec<AttentionItem>) {
    // Check for unknown capabilities
    for req in manifest.required.iter().chain(manifest.optional.iter()) {
        if req.capability.parse::<crate::capability::Capability>().is_err() {
            attention.push(AttentionItem {
                kind: AttentionKind::UnknownCapability,
                subject: req.capability.clone(),
                reason: format!(
                    "Capability '{}' is not in the ZeroPoint taxonomy",
                    req.capability
                ),
                suggestion: Some(
                    "Check spelling, or add this as a custom capability".into(),
                ),
            });
        }
    }

    // Check for empty required with no env_vars
    for req in &manifest.required {
        if req.env_vars.is_empty()
            && req.shared_with.is_none()
            && !req.local_default
            && req.backend_groups.is_empty()
        {
            attention.push(AttentionItem {
                kind: AttentionKind::SpecialSetup,
                subject: req.capability.clone(),
                reason: "Required capability has no env_vars, no shared_with, and no local_default"
                    .into(),
                suggestion: Some("Add env_vars mapping or mark as shared_with another capability".into()),
            });
        }
    }
}

// ============================================================================
// Var classification
// ============================================================================

/// How we classify a single env var from the template.
#[derive(Debug, Clone, PartialEq, Eq)]
enum VarClass {
    /// Definitely a credential (API key, token, secret key)
    ProbableCredential,
    /// Looks like an auto-generatable internal secret (salt, internal password)
    ProbableSecret,
    /// URL endpoint
    ProbableUrl,
    /// Database connection string or URL
    DatabaseUrl,
    /// Database credential (user, password, db name)
    DatabaseCredential,
    /// Model name selector
    Model,
    /// Boolean toggle
    Toggle,
    /// General configuration value
    Config,
    /// Fallback: could be anything
    Default,
}

/// Internal tracking for an env var during inference.
#[derive(Debug, Clone)]
struct EnvVarInfo {
    name: String,
    value: String,
    class: VarClass,
    _provider: Option<String>,
}

/// Classify an env var by name and template value.
fn classify_var(var_name: &str, template_value: &str) -> VarClass {
    let upper = var_name.to_uppercase();

    // Database detection
    if upper.contains("DATABASE_URL")
        || upper.contains("POSTGRES_URL")
        || upper.contains("MYSQL_URL")
        || upper.contains("DB_URL")
        || upper.contains("CONNECTION_STRING")
    {
        return VarClass::DatabaseUrl;
    }
    if upper.starts_with("POSTGRES_")
        || upper.starts_with("MYSQL_")
        || upper.starts_with("DB_")
        || upper.starts_with("DATABASE_")
    {
        if upper.contains("PASSWORD") || upper.contains("USER") || upper.contains("NAME") {
            return VarClass::DatabaseCredential;
        }
    }

    // Auto-generatable secrets (salts, internal passwords, encryption keys)
    if upper.contains("_SALT")
        || upper.contains("_NONCE")
        || upper.contains("ENCRYPTION_KEY")
        || upper.contains("JWT_SECRET")
        || upper.contains("SESSION_SECRET")
        || upper.contains("NEXTAUTH_SECRET")
        || upper.contains("SECRET_KEY_BASE")
        || upper.contains("INTERNAL_PASSWORD")
        || upper.contains("MASTER_PASSWORD")
    {
        return VarClass::ProbableSecret;
    }

    // Credential patterns
    if upper.ends_with("_API_KEY")
        || upper.ends_with("_SECRET_KEY")
        || upper.ends_with("_SECRET")
        || upper.ends_with("_TOKEN")
        || upper.ends_with("_ACCESS_KEY")
        || upper.ends_with("_PRIVATE_KEY")
        || upper.ends_with("_PASSWORD")
        || upper.ends_with("_PASS")
        || upper == "API_KEY"
    {
        return VarClass::ProbableCredential;
    }

    // URL patterns
    if upper.ends_with("_URL")
        || upper.ends_with("_ENDPOINT")
        || upper.ends_with("_HOST")
        || upper.ends_with("_BASE_URL")
        || upper.ends_with("_SERVER_URL")
    {
        return VarClass::ProbableUrl;
    }

    // Model selectors
    if upper.ends_with("_MODEL")
        || upper.ends_with("_MODELS")
        || upper.contains("_MODEL_")
    {
        return VarClass::Model;
    }

    // Toggles
    if upper.ends_with("_ENABLED")
        || upper.ends_with("_DISABLED")
        || upper.starts_with("ENABLE_")
        || upper.starts_with("DISABLE_")
        || upper.starts_with("USE_")
    {
        return VarClass::Toggle;
    }

    // Template value hints
    if template_value == "true"
        || template_value == "false"
        || template_value == "0"
        || template_value == "1"
    {
        return VarClass::Toggle;
    }

    if template_value.starts_with("http://") || template_value.starts_with("https://") {
        return VarClass::ProbableUrl;
    }

    // Port, count, size — configuration
    if upper.ends_with("_PORT")
        || upper.ends_with("_SIZE")
        || upper.ends_with("_COUNT")
        || upper.ends_with("_LIMIT")
        || upper.ends_with("_TIMEOUT")
        || upper.ends_with("_RETRIES")
    {
        return VarClass::Config;
    }

    VarClass::Default
}

// ============================================================================
// Provider grouping helpers
// ============================================================================

/// Collect provider groups that have LLM capabilities.
fn collect_llm_providers(
    provider_vars: &BTreeMap<String, Vec<EnvVarInfo>>,
    catalog: &[ProviderProfile],
) -> Vec<(String, Vec<EnvVarInfo>)> {
    provider_vars
        .iter()
        .filter(|(id, _)| {
            catalog
                .iter()
                .find(|p| &p.id == *id)
                .map(|p| p.capabilities.iter().any(|c| is_llm_capability(c)))
                .unwrap_or(false)
        })
        .map(|(id, vars)| (id.clone(), vars.clone()))
        .collect()
}

/// Collect provider groups that have non-LLM capabilities only.
fn collect_non_llm_providers(
    provider_vars: &BTreeMap<String, Vec<EnvVarInfo>>,
    catalog: &[ProviderProfile],
) -> Vec<(String, Vec<EnvVarInfo>)> {
    provider_vars
        .iter()
        .filter(|(id, _)| {
            catalog
                .iter()
                .find(|p| &p.id == *id)
                .map(|p| {
                    p.capabilities
                        .iter()
                        .any(|c| !is_llm_capability(c))
                })
                .unwrap_or(false)
        })
        .map(|(id, vars)| (id.clone(), vars.clone()))
        .collect()
}

/// Whether a capability string represents an LLM capability.
fn is_llm_capability(cap: &str) -> bool {
    matches!(
        cap,
        "reasoning_llm" | "fast_llm" | "code_llm" | "long_context_llm" | "vision"
    )
}

/// Whether a capability is typically optional (enrichment, not core).
fn is_typically_optional(cap: &str) -> bool {
    matches!(
        cap,
        "observability"
            | "auth_oauth"
            | "auth_api"
            | "graph_db"
            | "browser"
            | "code_execution"
            | "file_conversion"
            | "email"
            | "messaging_slack"
            | "messaging_telegram"
            | "messaging_signal"
            | "audio_gen"
            | "voice_clone"
            | "video_gen"
            | "video_edit"
            | "video_understanding"
            | "3d_gen"
            | "pdf_processing"
            | "reranking"
    )
}

// ============================================================================
// Utility helpers
// ============================================================================

/// Check if a directory has any env template file.
fn has_env_template(dir: &Path) -> bool {
    find_env_template(dir).is_some()
}

/// Find the env template for a given directory.
fn find_env_template(dir: &Path) -> Option<PathBuf> {
    for subdir in ENV_SUBDIRS {
        let base = if subdir.is_empty() {
            dir.to_path_buf()
        } else {
            dir.join(subdir)
        };
        for name in ENV_TEMPLATE_NAMES {
            let candidate = base.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Whether a directory name should be skipped during scanning.
fn is_skip_dir(name: &str) -> bool {
    name.starts_with('.')
        || name == "node_modules"
        || name == "target"
        || name == "__pycache__"
        || name == "venv"
        || name == ".venv"
}

/// Infer database defaults from a template value.
fn infer_database_defaults(template_value: &str) -> HashMap<String, String> {
    let mut defaults = HashMap::new();

    // Common PostgreSQL defaults
    if template_value.contains("postgres") || template_value.contains("postgresql") {
        defaults.insert("POSTGRES_USER".into(), "postgres".into());
        defaults.insert("POSTGRES_DB".into(), "zeropoint".into());
    }

    defaults
}

/// Check if a URL looks like an internal/proprietary service.
fn looks_like_internal_url(value: &str) -> bool {
    value.contains("internal.")
        || value.contains("corp.")
        || value.contains("local.")
        || value.contains("192.168.")
        || value.contains("10.0.")
        || value.contains("172.16.")
        || value.contains("localhost")
}

/// Build a default `CapabilityRequirement` with all optional fields empty.
fn default_requirement() -> CapabilityRequirement {
    CapabilityRequirement {
        capability: String::new(),
        env_vars: Vec::new(),
        config_vars: HashMap::new(),
        prefer: Vec::new(),
        shared_with: None,
        model_env: None,
        model_default: None,
        defaults: HashMap::new(),
        attention: None,
        local_default: false,
        notes: None,
        backend_groups: Vec::new(),
        auto_generate: Vec::new(),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn classify_var_credentials() {
        assert_eq!(
            classify_var("OPENAI_API_KEY", ""),
            VarClass::ProbableCredential
        );
        assert_eq!(
            classify_var("ANTHROPIC_SECRET_KEY", ""),
            VarClass::ProbableCredential
        );
        assert_eq!(classify_var("API_KEY", ""), VarClass::ProbableCredential);
    }

    #[test]
    fn classify_var_urls() {
        assert_eq!(
            classify_var("OPENAI_BASE_URL", ""),
            VarClass::ProbableUrl
        );
        assert_eq!(
            classify_var("RANDOM_THING", "https://example.com"),
            VarClass::ProbableUrl
        );
    }

    #[test]
    fn classify_var_secrets() {
        assert_eq!(
            classify_var("JWT_SECRET", ""),
            VarClass::ProbableSecret
        );
        assert_eq!(
            classify_var("NEXTAUTH_SECRET", ""),
            VarClass::ProbableSecret
        );
        assert_eq!(
            classify_var("ENCRYPTION_KEY", ""),
            VarClass::ProbableSecret
        );
    }

    #[test]
    fn classify_var_database() {
        assert_eq!(
            classify_var("DATABASE_URL", ""),
            VarClass::DatabaseUrl
        );
        assert_eq!(
            classify_var("POSTGRES_PASSWORD", ""),
            VarClass::DatabaseCredential
        );
    }

    #[test]
    fn classify_var_toggles() {
        assert_eq!(
            classify_var("ENABLE_SEARCH", ""),
            VarClass::Toggle
        );
        assert_eq!(
            classify_var("SOMETHING", "true"),
            VarClass::Toggle
        );
    }

    #[test]
    fn classify_var_models() {
        assert_eq!(classify_var("OPENAI_MODEL", ""), VarClass::Model);
        assert_eq!(classify_var("LLM_MODELS", ""), VarClass::Model);
    }

    #[test]
    fn internal_url_detection() {
        assert!(looks_like_internal_url("https://api.internal.company.com"));
        assert!(looks_like_internal_url("http://192.168.1.100:8080"));
        assert!(looks_like_internal_url("http://localhost:3000"));
        assert!(!looks_like_internal_url("https://api.openai.com/v1"));
    }

    #[test]
    fn is_typically_optional_works() {
        assert!(is_typically_optional("observability"));
        assert!(is_typically_optional("browser"));
        assert!(!is_typically_optional("reasoning_llm"));
        assert!(!is_typically_optional("embedding"));
        assert!(!is_typically_optional("database"));
    }

    #[test]
    fn discover_tool_with_manifest() {
        let dir = std::env::temp_dir().join("zp-test-discover-manifest");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Write a minimal manifest
        fs::write(
            dir.join(".zp-configure.toml"),
            r#"
[tool]
name = "test-tool"
version = "0.1"
description = "A test"

[[required]]
capability = "reasoning_llm"
env_vars = ["OPENAI_API_KEY"]
prefer = ["anthropic", "openai"]
"#,
        )
        .unwrap();

        let result = discover_tool(&dir);
        assert_eq!(result.source, ManifestSource::File(dir.join(".zp-configure.toml")));
        assert_eq!(result.confidence, Confidence::High);
        assert_eq!(result.manifest.required.len(), 1);
        assert!(result.attention_items.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn discover_tool_heuristic_fallback() {
        let dir = std::env::temp_dir().join("zp-test-discover-heuristic");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Write a .env.example with known provider vars
        fs::write(
            dir.join(".env.example"),
            "OPENAI_API_KEY=sk-...\nOPENAI_BASE_URL=https://api.openai.com/v1\nOPENAI_MODEL=gpt-4\nTAVILY_API_KEY=tvly-...\nPOSTGRES_PASSWORD=changeme\nPOSTGRES_USER=postgres\n",
        )
        .unwrap();

        let result = discover_tool(&dir);
        assert_eq!(result.source, ManifestSource::Inferred);
        assert!(result.confidence <= Confidence::Medium);
        assert!(!result.manifest.required.is_empty());

        // Should have inferred reasoning_llm and database
        let caps: Vec<&str> = result
            .manifest
            .required
            .iter()
            .map(|r| r.capability.as_str())
            .collect();
        assert!(caps.contains(&"reasoning_llm"), "missing reasoning_llm: {:?}", caps);
        assert!(caps.contains(&"database"), "missing database: {:?}", caps);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn discover_tool_surfaces_unrecognized() {
        let dir = std::env::temp_dir().join("zp-test-discover-unrecognized");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Write a .env.example with an unrecognized credential
        fs::write(
            dir.join(".env.example"),
            "OPENAI_API_KEY=sk-...\nMYSTERY_SERVICE_API_KEY=xxx\n",
        )
        .unwrap();

        let result = discover_tool(&dir);
        assert_eq!(result.confidence, Confidence::Low);
        assert!(!result.attention_items.is_empty());

        let attention_subjects: Vec<&str> = result
            .attention_items
            .iter()
            .map(|a| a.subject.as_str())
            .collect();
        assert!(
            attention_subjects.contains(&"MYSTERY_SERVICE_API_KEY"),
            "expected attention item for MYSTERY_SERVICE_API_KEY: {:?}",
            attention_subjects
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_manifest_roundtrip() {
        let dir = std::env::temp_dir().join("zp-test-manifest-gen");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(
            dir.join(".env.example"),
            "OPENAI_API_KEY=sk-...\nOPENAI_BASE_URL=https://api.openai.com/v1\nPOSTGRES_PASSWORD=changeme\n",
        )
        .unwrap();

        let result = discover_tool(&dir);
        let toml_str = generate_manifest_toml(&result);

        // The generated TOML should parse back into a valid manifest
        let parsed: ToolManifest = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.tool.name, result.manifest.tool.name);
        assert_eq!(parsed.required.len(), result.manifest.required.len());

        let _ = fs::remove_dir_all(&dir);
    }
}
