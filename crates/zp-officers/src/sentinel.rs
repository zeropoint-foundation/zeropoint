//! Sentinel (Sen) — Security officer.
//!
//! Domain: Credential lifecycle, authentication integrity, access anomalies.
//! Proposes rotation and revocation. Never executes either.
//!
//! Watches the chain for gate denial patterns, delegation health, and
//! identity coherence. Watches vault key names for credential hygiene
//! (freshness signals, plaintext leak patterns). Reports security facts.
//! Doesn't make integrity judgments (Steward) or operational judgments (Forge).

use std::collections::HashMap;

use chrono::Utc;
use serde_json::json;
use tracing::debug;

use crate::chain_reads::{classify_delegation, classify_gate, DelegationKind, GateOutcome};
use crate::finding::{Finding, Severity};
use crate::officer::{ChainReader, Officer, VaultKeyLister};
use zp_core::AuditEntry;

/// The Sentinel officer — watches credential lifecycle, auth integrity,
/// and access anomalies.
pub struct Sentinel;

impl Default for Sentinel {
    fn default() -> Self {
        Self::new()
    }
}

impl Sentinel {
    pub fn new() -> Self {
        Self
    }

    /// Analyze gate denial patterns for clusters or anomalies.
    ///
    /// Looks for:
    /// - High denial rate (more denials than allows)
    /// - Denial clusters (3+ denials in 60 seconds)
    /// - Repeated denials for the same actor (identity coherence issue)
    fn check_gate_denial_patterns(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();
        let mut denied_entries: Vec<&AuditEntry> = Vec::new();
        let mut allowed_count = 0usize;
        let mut denied_by_actor: HashMap<String, usize> = HashMap::new();

        for entry in &entries {
            if let Some(ev) = classify_gate(entry) {
                match ev.outcome {
                    GateOutcome::Denied => {
                        denied_entries.push(entry);
                        let actor = actor_label(&entry.actor);
                        *denied_by_actor.entry(actor).or_insert(0) += 1;
                    }
                    GateOutcome::Allowed => {
                        allowed_count += 1;
                    }
                }
            }
        }

        let denied_count = denied_entries.len();
        let total = denied_count + allowed_count;

        // High denial rate
        if total > 10 && denied_count > allowed_count {
            let ratio = denied_count as f64 / total as f64;
            findings.push(Finding {
                officer: self.name(),
                domain: self.domain(),
                finding_type: "high_denial_rate".into(),
                severity: Severity::Warning,
                summary: format!(
                    "Gate denial rate {:.0}%: {} denied of {} total decisions",
                    ratio * 100.0,
                    denied_count,
                    total
                ),
                detail: json!({
                    "denied": denied_count,
                    "allowed": allowed_count,
                    "ratio": ratio,
                }),
                timestamp: Utc::now(),
                cross_domain_depth: 0,
            });
        }

        // Denial clusters — 3+ within 60 seconds
        if denied_entries.len() >= 3 {
            let mut cluster_start = 0usize;
            for i in 2..denied_entries.len() {
                let window = denied_entries[i].timestamp - denied_entries[cluster_start].timestamp;
                if window.num_seconds() <= 60 {
                    // We have at least 3 in 60s
                    let cluster_size = i - cluster_start + 1;
                    if cluster_size >= 3 {
                        findings.push(Finding {
                            officer: self.name(),
                            domain: self.domain(),
                            finding_type: "denial_cluster".into(),
                            severity: Severity::Warning,
                            summary: format!(
                                "{} gate denials within 60 seconds — possible access anomaly",
                                cluster_size
                            ),
                            detail: json!({
                                "cluster_size": cluster_size,
                                "window_seconds": 60,
                                "first_timestamp": denied_entries[cluster_start].timestamp.to_rfc3339(),
                                "last_timestamp": denied_entries[i].timestamp.to_rfc3339(),
                            }),
                            timestamp: Utc::now(),
                            cross_domain_depth: 0,
                        });
                        break; // One cluster finding per sweep
                    }
                } else {
                    cluster_start = i - 1;
                }
            }
        }

        // Repeated denials for the same actor
        for (actor, count) in &denied_by_actor {
            if *count >= 5 {
                findings.push(Finding {
                    officer: self.name(),
                    domain: self.domain(),
                    finding_type: "repeated_actor_denial".into(),
                    severity: Severity::Warning,
                    summary: format!(
                        "Actor '{}' denied {} times — possible identity coherence issue",
                        actor, count
                    ),
                    detail: json!({
                        "actor": actor,
                        "denial_count": count,
                    }),
                    timestamp: Utc::now(),
                    cross_domain_depth: 0,
                });
            }
        }

        findings
    }

    /// Check delegation health: orphaned grants, high revocation rate.
    fn check_delegation_health(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();
        let mut active_grants: HashMap<String, usize> = HashMap::new();
        let mut revocations = 0usize;
        let mut total_grants = 0usize;

        for entry in &entries {
            if let Some(ev) = classify_delegation(entry) {
                match ev.kind {
                    DelegationKind::Granted => {
                        *active_grants.entry(ev.target).or_insert(0) += 1;
                        total_grants += 1;
                    }
                    DelegationKind::Revoked => {
                        active_grants.remove(&ev.target);
                        revocations += 1;
                    }
                    DelegationKind::Expired => {
                        active_grants.remove(&ev.target);
                    }
                    DelegationKind::Renewed => {}
                }
            }
        }

        // High revocation ratio — security concern if many grants get revoked
        if total_grants > 5 && revocations > 0 {
            let ratio = revocations as f64 / total_grants as f64;
            if ratio > 0.5 {
                findings.push(Finding {
                    officer: self.name(),
                    domain: self.domain(),
                    finding_type: "high_revocation_rate".into(),
                    severity: Severity::Info,
                    summary: format!(
                        "{} of {} delegations revoked ({:.0}%) — review delegation lifecycle",
                        revocations,
                        total_grants,
                        ratio * 100.0
                    ),
                    detail: json!({
                        "revocations": revocations,
                        "total_grants": total_grants,
                        "ratio": ratio,
                    }),
                    timestamp: Utc::now(),
                    cross_domain_depth: 0,
                });
            }
        }

        // Multiple active grants for the same subject — possible scope creep
        for (subject, count) in &active_grants {
            if *count > 3 {
                findings.push(Finding {
                    officer: self.name(),
                    domain: self.domain(),
                    finding_type: "delegation_accumulation".into(),
                    severity: Severity::Warning,
                    summary: format!(
                        "Subject '{}' has {} active delegation grants — possible scope creep",
                        subject, count
                    ),
                    detail: json!({
                        "subject": subject,
                        "grant_count": count,
                    }),
                    timestamp: Utc::now(),
                    cross_domain_depth: 0,
                });
            }
        }

        findings
    }

    /// Check vault keys for credential hygiene concerns.
    ///
    /// Focuses on security-relevant signals that Steward doesn't cover:
    /// - Credential naming patterns suggesting plaintext leaks
    /// - Missing expected credential namespaces
    /// - Duplicate credentials across namespaces (shadow keys)
    fn check_credential_hygiene(&self, vault_keys: &VaultKeyLister) -> Vec<Finding> {
        let mut findings = Vec::new();
        let keys = vault_keys.all_keys();

        if keys.is_empty() {
            return findings;
        }

        // Check for plaintext secret patterns in key names (beyond Steward's
        // suspicious_patterns — Sentinel looks for full credential values)
        let credential_patterns = [
            "sk-ant-",    // Anthropic API key
            "sk-proj-",   // OpenAI project API key
            "ghp_",       // GitHub personal access token
            "gho_",       // GitHub OAuth token
            "glpat-",     // GitLab personal access token
            "xoxb-",      // Slack bot token
            "xoxp-",      // Slack user token
            "AKIA",       // AWS access key
            "eyJ",        // JWT prefix (base64 of {"...)
            "-----BEGIN", // PEM key material
        ];

        for key in keys {
            for pattern in &credential_patterns {
                if key.contains(pattern) {
                    findings.push(Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: "credential_in_key_name".into(),
                        severity: Severity::Error,
                        summary: format!(
                            "Vault key name contains credential pattern '{}' — likely plaintext secret stored as key name",
                            pattern
                        ),
                        detail: json!({
                            "key": key,
                            "pattern": pattern,
                        }),
                        timestamp: Utc::now(),
                        cross_domain_depth: 0,
                    });
                }
            }
        }

        // Check for shadow keys — same variable name under different namespaces.
        //
        // Two-stage classification (added 2026-07-24 per task #12, mirroring the
        // P1.2 refactor that added benign-listener classification for
        // `unauthorized_listener`):
        //
        // 1. **Classify**: is the variable name a generic config field name
        //    (`API_KEY`, `TOKEN`, `URL`, `HOST`, ...) that legitimately appears
        //    under multiple tool namespaces because most tools have their own
        //    instance of the same field? If so, emit low-severity
        //    `generic_config_field_name` finding for auditability without
        //    treating it as a drift signal.
        //
        // 2. **Full flag**: for genuinely unusual variable names appearing under
        //    multiple namespaces (custom secrets, project-specific token names,
        //    migration leftovers), keep Warning-level `shadow_credential`.
        //
        // Composes with the octopus-shape / autonomic-coordination discipline
        // (KEEL III.25): routine multi-namespace usage of generic field names
        // should not crowd Regent's cognitive context. Signal quality is
        // structural coordination hygiene, not aesthetic preference.
        let mut var_names: HashMap<String, Vec<String>> = HashMap::new();
        for key in keys {
            if let Some(var_name) = key.rsplit('/').next() {
                var_names
                    .entry(var_name.to_string())
                    .or_default()
                    .push(key.to_string());
            }
        }

        for (var, paths) in &var_names {
            if paths.len() > 1 {
                // Only flag if they're under different namespace prefixes
                let namespaces: std::collections::HashSet<&str> = paths
                    .iter()
                    .filter_map(|p| p.rsplit_once('/').map(|(ns, _)| ns))
                    .collect();
                if namespaces.len() > 1 {
                    // Stage 1: classify against known-generic config field names.
                    if let Some(class) = Self::classify_generic_config_field(var) {
                        findings.push(Finding {
                            officer: self.name(),
                            domain: self.domain(),
                            finding_type: "generic_config_field_name".into(),
                            severity: Severity::Info,
                            summary: format!(
                                "Generic config field '{}' (class {}) appears under {} namespaces — routine multi-tool config, informational only",
                                var,
                                class,
                                namespaces.len()
                            ),
                            detail: json!({
                                "variable": var,
                                "field_class": class,
                                "paths": paths,
                                "namespaces": namespaces.iter().collect::<Vec<_>>(),
                                "classification_rationale": "Generic config field names legitimately appear under multiple tool namespaces because most tools maintain their own instance of the same field. This is routine multi-tool configuration, not credential drift.",
                            }),
                            timestamp: Utc::now(),
                            cross_domain_depth: 0,
                        });
                        continue;
                    }

                    // Stage 2: unusual variable name under multiple namespaces —
                    // real drift signal or unexpected pattern worth surfacing.
                    findings.push(Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: "shadow_credential".into(),
                        severity: Severity::Warning,
                        summary: format!(
                            "Variable '{}' exists under {} namespaces — possible credential drift",
                            var,
                            namespaces.len()
                        ),
                        detail: json!({
                            "variable": var,
                            "paths": paths,
                            "namespaces": namespaces.iter().collect::<Vec<_>>(),
                        }),
                        timestamp: Utc::now(),
                        cross_domain_depth: 0,
                    });
                }
            }
        }

        findings
    }

    /// Classify a variable name against known-generic config field name classes.
    ///
    /// Returns `Some(class_name)` if the variable is a common config field name
    /// that legitimately appears under multiple tool namespaces. Returns `None`
    /// for genuinely unusual variable names.
    ///
    /// **Design intent** (added 2026-07-24 per task #12, P1.2 pattern):
    /// Sentinel's `shadow_credential` check was producing false-positives on
    /// normal substrate configuration — most tools share config field names
    /// like `API_KEY`, `TOKEN`, `URL`, `HOST`, `PORT`. These are not drift
    /// signals; they're the natural shape of multi-tool config. This classifier
    /// separates *variable-name genericness* (routine, Info) from *unusual-name
    /// multi-namespace usage* (potentially drift, Warning).
    ///
    /// **Aligned-blindness composition** (KEEL III.24): Sentinel sees key
    /// *names* only, never values. Classification is name-shape only —
    /// no value inspection, no cross-namespace value comparison. Preserves
    /// the substrate's structural blindness discipline.
    ///
    /// **Class taxonomy**:
    /// - `credential`: generic credential/secret field names
    /// - `endpoint`: URL/host/port/network-target fields
    /// - `identity`: user/account/client-ID fields
    /// - `database`: DB connection fields
    /// - `region`: cloud region/zone/account fields
    /// - `timing`: timeout/retry/cadence fields
    ///
    /// Extension via canonicalization: as new tool categories land with novel
    /// canonical field names, they get added here. Signal-quality decisions
    /// remain evidence-based per SUBSTRATE-COORDINATION-DISCIPLINE (KEEL III.25).
    fn classify_generic_config_field(var: &str) -> Option<&'static str> {
        // Normalize: uppercase for comparison (config names are conventionally
        // uppercase, but tolerate mixed case).
        let upper = var.to_uppercase();

        // Credential class — generic secret/token/key/password field names.
        const CREDENTIAL_NAMES: &[&str] = &[
            "API_KEY",
            "APIKEY",
            "API_TOKEN",
            "APITOKEN",
            "API_SECRET",
            "TOKEN",
            "AUTH_TOKEN",
            "ACCESS_TOKEN",
            "REFRESH_TOKEN",
            "SECRET",
            "SECRET_KEY",
            "APP_SECRET",
            "APP_KEY",
            "PASSWORD",
            "PASS",
            "PWD",
            "KEY",
            "PRIVATE_KEY",
            "PUBLIC_KEY",
            "CLIENT_SECRET",
            "SIGNING_KEY",
            "ENCRYPTION_KEY",
            "WEBHOOK_SECRET",
            "SESSION_SECRET",
        ];
        if CREDENTIAL_NAMES.contains(&upper.as_str()) {
            return Some("credential");
        }

        // Endpoint class — network target field names.
        const ENDPOINT_NAMES: &[&str] = &[
            "URL",
            "API_URL",
            "BASE_URL",
            "ENDPOINT",
            "API_ENDPOINT",
            "HOST",
            "HOSTNAME",
            "SERVER",
            "SERVER_URL",
            "PORT",
            "API_PORT",
            "WEBHOOK_URL",
            "CALLBACK_URL",
            "REDIRECT_URL",
            "REDIRECT_URI",
        ];
        if ENDPOINT_NAMES.contains(&upper.as_str()) {
            return Some("endpoint");
        }

        // Identity class — user/account/client identifiers.
        const IDENTITY_NAMES: &[&str] = &[
            "USER",
            "USERNAME",
            "USER_NAME",
            "USER_ID",
            "USERID",
            "ACCOUNT",
            "ACCOUNT_ID",
            "ACCOUNT_NAME",
            "CLIENT_ID",
            "APP_ID",
            "APPLICATION_ID",
            "TENANT_ID",
            "ORG_ID",
            "ORGANIZATION_ID",
            "EMAIL",
            "LOGIN",
        ];
        if IDENTITY_NAMES.contains(&upper.as_str()) {
            return Some("identity");
        }

        // Database class — DB connection field names.
        const DATABASE_NAMES: &[&str] = &[
            "DATABASE_URL",
            "DB_URL",
            "DB_HOST",
            "DB_PORT",
            "DB_NAME",
            "DB_USER",
            "DB_USERNAME",
            "DB_PASS",
            "DB_PASSWORD",
            "DATABASE_NAME",
            "DATABASE_HOST",
            "DATABASE_PORT",
            "DATABASE_USER",
            "DATABASE_PASSWORD",
            "CONNECTION_STRING",
            "CONNECTION_URL",
        ];
        if DATABASE_NAMES.contains(&upper.as_str()) {
            return Some("database");
        }

        // Region class — cloud region/zone/account fields.
        const REGION_NAMES: &[&str] = &[
            "REGION",
            "ZONE",
            "AVAILABILITY_ZONE",
            "AWS_REGION",
            "GCP_REGION",
            "AZURE_REGION",
            "DATACENTER",
            "LOCATION",
        ];
        if REGION_NAMES.contains(&upper.as_str()) {
            return Some("region");
        }

        // Timing class — timeout/retry/cadence field names.
        const TIMING_NAMES: &[&str] = &[
            "TIMEOUT",
            "REQUEST_TIMEOUT",
            "READ_TIMEOUT",
            "WRITE_TIMEOUT",
            "CONNECT_TIMEOUT",
            "IDLE_TIMEOUT",
            "RETRY",
            "MAX_RETRIES",
            "RETRY_COUNT",
            "INTERVAL",
            "POLL_INTERVAL",
            "SWEEP_INTERVAL",
        ];
        if TIMING_NAMES.contains(&upper.as_str()) {
            return Some("timing");
        }

        None
    }

    /// Classify a listening process against known-benign application classes.
    ///
    /// Returns `Some(class_name)` if the process matches a well-known operator
    /// application category (browser helper, IDE helper, messaging client,
    /// system daemon). Returns `None` for genuinely unknown listeners.
    ///
    /// Composes with the substrate's aligned-blindness discipline (KEEL III.24)
    /// and the coordination-not-oversight principle (KEEL III.23): normal user
    /// apps that happen to open sockets are not adversarial by default. Sentinel
    /// should not flag every browser helper and code editor helper as a
    /// security incident. Genuinely unknown listeners still get the full risk
    /// assessment; known-benign classes get downgraded severity and a distinct
    /// finding_type so operator cognitive attention isn't overwhelmed with
    /// false positives.
    ///
    /// Classification is currently hard-coded canonical set. When Task P2.1
    /// (standing correction data pipeline) lands, this classification will
    /// compose with operator-declared standing corrections about specific
    /// process classes — operator can extend the known-benign set for their
    /// substrate via chain-anchored corrections.
    fn classify_benign_listener_class(
        binary_path: &str,
        process_name: &str,
    ) -> Option<&'static str> {
        // macOS Application bundles — browsers, editors, messaging, media
        // apps that routinely open listening sockets for legitimate features
        // (WebRTC, IPC, plugin communication, local dev servers).
        const APPLICATION_KEYWORDS: &[(&str, &str)] = &[
            // Browsers
            ("Comet.app/", "browser_helper"),
            ("Brave Browser.app/", "browser_helper"),
            ("Google Chrome.app/", "browser_helper"),
            ("Safari.app/", "browser_helper"),
            ("Firefox.app/", "browser_helper"),
            ("Arc.app/", "browser_helper"),
            ("Chromium.app/", "browser_helper"),
            // Editors and IDE helpers
            ("Visual Studio Code.app/", "editor_helper"),
            ("Cursor.app/", "editor_helper"),
            ("Zed.app/", "editor_helper"),
            ("Sublime Text.app/", "editor_helper"),
            ("IntelliJ IDEA.app/", "editor_helper"),
            ("PyCharm.app/", "editor_helper"),
            ("WebStorm.app/", "editor_helper"),
            ("Xcode.app/", "editor_helper"),
            // Messaging / communication
            ("Slack.app/", "messaging_helper"),
            ("Signal.app/", "messaging_helper"),
            ("WhatsApp.app/", "messaging_helper"),
            ("Telegram.app/", "messaging_helper"),
            ("Discord.app/", "messaging_helper"),
            ("Zoom.us.app/", "messaging_helper"),
            ("Microsoft Teams.app/", "messaging_helper"),
            // AI / agent apps
            ("Claude.app/", "ai_client_helper"),
            ("ChatGPT.app/", "ai_client_helper"),
            // Local inference backends. Ollama spawns a fresh `llama-server`
            // per model load, each on a random high port bound to 127.0.0.1,
            // so it is a recurring source of genuinely-new listeners rather
            // than a one-off — edge-triggering suppresses repeats but cannot
            // suppress a real new process. Classified benign because it is the
            // operator's own inference backend; the substrate routes its
            // cognition through it.
            ("Ollama.app/", "inference_backend"),
            ("/llama-server", "inference_backend"),
            // Productivity
            ("Notion.app/", "productivity_helper"),
            ("Obsidian.app/", "productivity_helper"),
            ("Linear.app/", "productivity_helper"),
        ];

        // macOS system daemons that legitimately hold listening sockets under
        // /System/Library/PrivateFrameworks/ or /usr/libexec/. These are OS
        // infrastructure — flagging them as security incidents is noise.
        const SYSTEM_DAEMON_KEYWORDS: &[(&str, &str)] = &[
            ("/usr/libexec/sharingd", "system_daemon"),
            ("identityservicesd", "system_daemon"),
            ("ReplicatorCore.framework", "system_daemon"),
            ("bluetoothd", "system_daemon"),
            ("cloudphotod", "system_daemon"),
            ("networkd", "system_daemon"),
            ("mDNSResponder", "system_daemon"),
            ("rapportd", "system_daemon"),
            ("nsurlsessiond", "system_daemon"),
            ("cfprefsd", "system_daemon"),
            ("apsd", "system_daemon"),
            ("locationd", "system_daemon"),
        ];

        // Case-insensitive. Bundle directory casing is not something the
        // classifier gets to assume: Claude Code ships its helper at
        //
        //   …/Application Support/Claude/claude-code/2.1.219/claude.app/…
        //
        // — capitalised as a support directory, lowercase as the bundle. The
        // keyword `Claude.app/` matched neither, so every Claude Code start was
        // logged as a security incident. Found 2026-08-06, in the first receipt
        // payload after officer findings began carrying `binary_path` at all;
        // for as long as the classifier had existed the evidence needed to see
        // this was being computed and discarded.
        //
        // Lowercasing per call rather than at compile time: this runs once per
        // newly discovered listener, so the allocation is irrelevant next to
        // the `proc_pidpath` syscall that produced the path.
        let path_lc = binary_path.to_lowercase();
        let name_lc = process_name.to_lowercase();

        // Check binary_path first (most reliable — canonical bundle location)
        for (keyword, class) in APPLICATION_KEYWORDS {
            if path_lc.contains(&keyword.to_lowercase()) {
                return Some(class);
            }
        }
        for (keyword, class) in SYSTEM_DAEMON_KEYWORDS {
            let k = keyword.to_lowercase();
            if path_lc.contains(&k) || name_lc.contains(&k) {
                return Some(class);
            }
        }

        None
    }

    /// Assess an unregistered listening process from a security perspective.
    ///
    /// Sentinel evaluates: is this process a security concern? Two-stage:
    ///
    /// 1. Classification: is the process a well-known operator application
    ///    class (browser helper, IDE helper, messaging app, system daemon)?
    ///    If so, emit low-severity `unregistered_known_app` finding for
    ///    auditability without treating it as a security incident.
    ///
    /// 2. Full risk assessment for genuinely unknown listeners:
    ///    - Running as root/privileged user
    ///    - Binary not in standard system paths
    ///    - Unknown parent lineage (not launched by a known shell or init)
    ///    - Binding on non-loopback interfaces (network-exposed)
    ///
    /// The classification stage was added 2026-07-11 to address the substantial
    /// false-positive rate on normal user machines (per today's diagnostic:
    /// Sentinel was flagging every browser helper, editor helper, and system
    /// daemon as adversarial). See CLAUDE.md workflow heuristic
    /// "Aligned blindness is a moral property of the substrate" and KEEL III.23
    /// coordination-not-oversight — normal user apps opening sockets are not
    /// adversarial by default.
    ///
    /// Takes process context as JSON (same shape as `ProcessContext` from
    /// zp-sensors, passed as serde_json::Value to avoid crate dependency).
    pub fn assess_unauthorized_listener(
        &self,
        pid: u32,
        process_name: &str,
        ports: &[serde_json::Value],
        context: &serde_json::Value,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let binary_path = context
            .get("binary_path")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let user = context
            .get("user")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let parent_name = context.get("parent_name").and_then(|v| v.as_str());

        // Stage 1: classify against known-benign application classes.
        // Known-benign listeners emit low-severity `unregistered_known_app`
        // finding and skip the full risk-factor cascade. Genuinely unknown
        // listeners fall through to the full assessment.
        if let Some(class) = Self::classify_benign_listener_class(binary_path, process_name) {
            findings.push(Finding {
                officer: self.name(),
                domain: self.domain(),
                finding_type: "unregistered_known_app".into(),
                severity: Severity::Info,
                summary: format!(
                    "Known operator-app listener: '{}' (pid {}, class {}) — informational only",
                    process_name, pid, class
                ),
                detail: json!({
                    "pid": pid,
                    "process_name": process_name,
                    "binary_path": binary_path,
                    "user": user,
                    "benign_class": class,
                    "context": context,
                }),
                timestamp: Utc::now(),
                cross_domain_depth: 0,
            });
            return findings;
        }

        // Stage 2: full risk assessment for genuinely unknown listeners.
        let mut severity = Severity::Warning;
        let mut risk_factors: Vec<String> = Vec::new();

        // Escalate if running as root
        if user == "root" || user == "uid:0" {
            severity = Severity::Error;
            risk_factors.push("running as root".into());
        }

        // Escalate if binary is outside standard paths
        let standard_prefixes = [
            "/usr/",
            "/bin/",
            "/sbin/",
            "/System/",
            "/Applications/",
            "/Library/",
        ];
        if binary_path != "unknown" && !standard_prefixes.iter().any(|p| binary_path.starts_with(p))
        {
            risk_factors.push(format!("non-standard binary path: {binary_path}"));
        }

        // Check for network-exposed ports (non-loopback)
        let mut exposed_ports = Vec::new();
        for port_val in ports {
            if let Some(socket) = port_val.get("socket").and_then(|v| v.as_str()) {
                if !socket.starts_with("127.0.0.1")
                    && !socket.starts_with("[::1]")
                    && !socket.starts_with("localhost")
                {
                    if let Some(port) = port_val.get("port").and_then(|v| v.as_u64()) {
                        exposed_ports.push(port);
                    }
                }
            }
        }
        if !exposed_ports.is_empty() {
            severity = std::cmp::max(severity, Severity::Error);
            risk_factors.push(format!(
                "network-exposed on port(s): {}",
                exposed_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        // Unknown parent lineage
        let known_parents = [
            "launchd", "zsh", "bash", "fish", "sh", "login", "sshd", "tmux", "screen",
        ];
        if let Some(parent) = parent_name {
            if !known_parents.iter().any(|kp| parent.contains(kp)) {
                risk_factors.push(format!("unusual parent: {parent}"));
            }
        }

        let risk_summary = if risk_factors.is_empty() {
            "no elevated risk factors".to_string()
        } else {
            risk_factors.join("; ")
        };

        findings.push(Finding {
            officer: self.name(),
            domain: self.domain(),
            finding_type: "unauthorized_listener".into(),
            severity,
            summary: format!(
                "Unregistered process '{}' (pid {}) listening — {}",
                process_name, pid, risk_summary
            ),
            detail: json!({
                "pid": pid,
                "process_name": process_name,
                "context": context,
                "risk_factors": risk_factors,
                "exposed_ports": exposed_ports,
            }),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        });

        findings
    }

    /// Scan chain entries for plaintext secrets leaked into receipts.
    fn check_chain_secret_leaks(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(500) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();
        let secret_patterns = [
            "sk-ant-", "sk-proj-", "ghp_", "gho_", "xoxb-", "xoxp-", "AKIA",
        ];

        for entry in &entries {
            // Check the receipt detail (serialized metadata) for secrets
            if let Some(receipt) = &entry.receipt {
                let receipt_str = serde_json::to_string(receipt).unwrap_or_default();
                for pattern in &secret_patterns {
                    if receipt_str.contains(pattern) {
                        findings.push(Finding {
                            officer: self.name(),
                            domain: self.domain(),
                            finding_type: "secret_in_chain".into(),
                            severity: Severity::Critical,
                            summary: format!(
                                "Possible plaintext secret (pattern '{}') found in chain entry {}",
                                pattern, entry.id.0
                            ),
                            detail: json!({
                                "entry_id": entry.id.0.to_string(),
                                "pattern": pattern,
                                "timestamp": entry.timestamp.to_rfc3339(),
                            }),
                            timestamp: Utc::now(),
                            cross_domain_depth: 0,
                        });
                        break; // One finding per entry, even if multiple patterns match
                    }
                }
            }
        }

        findings
    }
}

/// Extract a human-readable label from an ActorId.
fn actor_label(actor: &zp_core::ActorId) -> String {
    match actor {
        zp_core::ActorId::System(s) => s.clone(),
        zp_core::ActorId::User(u) => u.clone(),
        _ => "unknown".into(),
    }
}

impl Officer for Sentinel {
    fn name(&self) -> &'static str {
        "sen"
    }

    fn domain(&self) -> &'static str {
        "security"
    }

    fn watch_patterns(&self) -> &[&'static str] {
        &["gate:denied:", "delegation:revoked:", "delegation:expired:"]
    }

    fn sweep(&self, chain: &ChainReader<'_>, vault_keys: &VaultKeyLister) -> Vec<Finding> {
        debug!("Sentinel sweep starting");

        let mut findings = Vec::new();

        findings.extend(self.check_gate_denial_patterns(chain));
        findings.extend(self.check_delegation_health(chain));
        findings.extend(self.check_credential_hygiene(vault_keys));
        findings.extend(self.check_chain_secret_leaks(chain));

        debug!(findings = findings.len(), "Sentinel sweep complete");

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::officer::{ChainReader, VaultKeyLister};
    use zp_audit::store::AuditStore;

    fn test_store() -> AuditStore {
        AuditStore::open_readonly(":memory:").expect("open in-memory store")
    }

    #[test]
    fn sentinel_trait_impl() {
        let sen = Sentinel::new();
        assert_eq!(sen.name(), "sen");
        assert_eq!(sen.domain(), "security");
        assert!(!sen.watch_patterns().is_empty());
        assert!(sen.watch_patterns().contains(&"gate:denied:"));
    }

    #[test]
    fn sentinel_sweep_empty_chain() {
        let store = test_store();
        let chain = ChainReader::new(&store);
        let vault = VaultKeyLister::new(vec![]);
        let sen = Sentinel::new();

        let findings = sen.sweep(&chain, &vault);
        // Empty chain + empty vault = no findings
        assert!(findings.is_empty());
    }

    #[test]
    fn sentinel_detects_credential_in_key_name() {
        let vault = VaultKeyLister::new(vec![
            "tools/example-tool/api_key".into(),
            "providers/anthropic/sk-ant-api03-real-key-value".into(), // leaked credential
            "tools/github/ghp_1234567890abcdef".into(),               // leaked GitHub token
        ]);

        let sen = Sentinel::new();
        let findings = sen.check_credential_hygiene(&vault);

        let leaks: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == "credential_in_key_name")
            .collect();

        assert_eq!(leaks.len(), 2);
        assert!(leaks.iter().any(|f| f.summary.contains("sk-ant-")));
        assert!(leaks.iter().any(|f| f.summary.contains("ghp_")));
    }

    #[test]
    fn sentinel_classifies_generic_api_key_as_benign() {
        // Post-2026-07-24 (task #12 refactor): API_KEY is a generic config
        // field name that legitimately appears under multiple namespaces.
        // Should emit Info-level `generic_config_field_name`, NOT Warning
        // `shadow_credential`.
        let vault = VaultKeyLister::new(vec![
            "tools/example-tool/API_KEY".into(),
            "providers/tools/example-tool/API_KEY".into(),
        ]);

        let sen = Sentinel::new();
        let findings = sen.check_credential_hygiene(&vault);

        // No shadow_credential findings (benign classification).
        let shadows: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == "shadow_credential")
            .collect();
        assert_eq!(
            shadows.len(),
            0,
            "API_KEY should classify as generic, not shadow"
        );

        // One generic_config_field_name at Info.
        let generic: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == "generic_config_field_name")
            .collect();
        assert_eq!(generic.len(), 1);
        assert_eq!(generic[0].severity, Severity::Info);
        assert!(generic[0].summary.contains("API_KEY"));
        assert_eq!(
            generic[0].detail["field_class"].as_str(),
            Some("credential")
        );
    }

    #[test]
    fn sentinel_flags_unusual_variable_name_as_shadow() {
        // A genuinely unusual variable name (not in the generic-config
        // taxonomy) appearing under multiple namespaces should still fire
        // shadow_credential at Warning — real drift signal preserved.
        let vault = VaultKeyLister::new(vec![
            "tools/myproject/CUSTOM_SPECIFIC_TOKEN_V3".into(),
            "legacy/myproject/CUSTOM_SPECIFIC_TOKEN_V3".into(),
        ]);

        let sen = Sentinel::new();
        let findings = sen.check_credential_hygiene(&vault);

        let shadows: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == "shadow_credential")
            .collect();
        assert_eq!(shadows.len(), 1);
        assert_eq!(shadows[0].severity, Severity::Warning);
        assert!(shadows[0].summary.contains("CUSTOM_SPECIFIC_TOKEN_V3"));
    }

    #[test]
    fn sentinel_classifies_endpoint_names_as_benign() {
        // URL/HOST/PORT are endpoint-class generic names — routine multi-tool.
        let vault = VaultKeyLister::new(vec![
            "tools/anthropic/URL".into(),
            "tools/openai/URL".into(),
            "tools/mistral/URL".into(),
        ]);

        let sen = Sentinel::new();
        let findings = sen.check_credential_hygiene(&vault);

        let generic: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == "generic_config_field_name")
            .collect();
        assert_eq!(generic.len(), 1);
        assert_eq!(generic[0].detail["field_class"].as_str(), Some("endpoint"));
    }

    #[test]
    fn sentinel_classifies_database_names_as_benign() {
        let vault = VaultKeyLister::new(vec![
            "tools/app_a/DB_HOST".into(),
            "tools/app_b/DB_HOST".into(),
        ]);

        let sen = Sentinel::new();
        let findings = sen.check_credential_hygiene(&vault);

        let generic: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == "generic_config_field_name")
            .collect();
        assert_eq!(generic.len(), 1);
        assert_eq!(generic[0].detail["field_class"].as_str(), Some("database"));
    }

    #[test]
    fn sentinel_classifier_is_case_insensitive() {
        // Variable names come in mixed cases; classifier should uppercase-compare.
        let vault = VaultKeyLister::new(vec![
            "tools/app_a/api_key".into(), // lowercase
            "tools/app_b/Api_Key".into(), // mixed
        ]);

        let sen = Sentinel::new();
        let findings = sen.check_credential_hygiene(&vault);

        // These have different exact variable-name spelling, so they DON'T
        // collide as shadow. But confirm the classifier itself is case-insensitive
        // via direct function call.
        assert_eq!(
            Sentinel::classify_generic_config_field("api_key"),
            Some("credential")
        );
        assert_eq!(
            Sentinel::classify_generic_config_field("Api_Key"),
            Some("credential")
        );
        assert_eq!(
            Sentinel::classify_generic_config_field("API_KEY"),
            Some("credential")
        );

        // No findings from vault (different spellings don't collide in var_names).
        assert!(findings.is_empty());
    }

    #[test]
    fn sentinel_classifier_returns_none_for_unusual_names() {
        // Confirm the classifier returns None for genuinely unusual names.
        assert_eq!(
            Sentinel::classify_generic_config_field("CUSTOM_SPECIFIC_TOKEN_V3"),
            None
        );
        assert_eq!(
            Sentinel::classify_generic_config_field("MY_APP_MAGIC_STRING"),
            None
        );
        assert_eq!(
            Sentinel::classify_generic_config_field("PROJECT_INTERNAL_KEY_ID"),
            None
        );
    }

    #[test]
    fn sentinel_classifies_across_all_six_classes() {
        // Sanity-check every declared class has at least one representative.
        assert_eq!(
            Sentinel::classify_generic_config_field("TOKEN"),
            Some("credential")
        );
        assert_eq!(
            Sentinel::classify_generic_config_field("HOST"),
            Some("endpoint")
        );
        assert_eq!(
            Sentinel::classify_generic_config_field("USERNAME"),
            Some("identity")
        );
        assert_eq!(
            Sentinel::classify_generic_config_field("DATABASE_URL"),
            Some("database")
        );
        assert_eq!(
            Sentinel::classify_generic_config_field("REGION"),
            Some("region")
        );
        assert_eq!(
            Sentinel::classify_generic_config_field("TIMEOUT"),
            Some("timing")
        );
    }

    #[test]
    fn sentinel_shadow_check_still_requires_multiple_namespaces() {
        // A variable name appearing in only one namespace (even with multiple
        // paths) should not emit any finding — the check is namespace-diversity,
        // not path-count. Behavior preserved from pre-refactor.
        let vault = VaultKeyLister::new(vec!["tools/only_here/CUSTOM_TOKEN".into()]);

        let sen = Sentinel::new();
        let findings = sen.check_credential_hygiene(&vault);

        // Single-namespace usage produces no drift finding of either class.
        let drift: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.finding_type == "shadow_credential"
                    || f.finding_type == "generic_config_field_name"
            })
            .collect();
        assert_eq!(drift.len(), 0);
    }

    #[test]
    fn sentinel_assesses_unauthorized_listener_basic() {
        let sen = Sentinel::new();
        let context = json!({
            "pid": 12345,
            "name": "mystery",
            "binary_path": "/usr/local/bin/mystery",
            "user": "ken",
            "parent_name": "zsh"
        });
        let ports = vec![json!({"port": 8080, "protocol": "TCP", "socket": "127.0.0.1:8080"})];

        let findings = sen.assess_unauthorized_listener(12345, "mystery", &ports, &context);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "unauthorized_listener");
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn sentinel_classifies_browser_helper_as_benign() {
        let sen = Sentinel::new();
        let context = json!({
            "pid": 57104,
            "name": "Comet Helper",
            "binary_path": "/Applications/Comet.app/Contents/Frameworks/Comet Helper.app/Contents/MacOS/Comet Helper",
            "user": "ken",
            "parent_name": "Comet"
        });
        let ports = vec![json!({"port": 51423, "protocol": "TCP", "socket": "0.0.0.0:51423"})];

        let findings = sen.assess_unauthorized_listener(57104, "Comet Helper", &ports, &context);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "unregistered_known_app");
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].summary.contains("browser_helper"));
    }

    #[test]
    fn sentinel_classifies_editor_helper_as_benign() {
        let sen = Sentinel::new();
        let context = json!({
            "pid": 42949,
            "name": "Code Helper",
            "binary_path": "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper",
            "user": "ken",
            "parent_name": "Code"
        });
        let ports = vec![json!({"port": 47812, "protocol": "TCP", "socket": "127.0.0.1:47812"})];

        let findings = sen.assess_unauthorized_listener(42949, "Code Helper", &ports, &context);
        assert_eq!(findings[0].finding_type, "unregistered_known_app");
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].summary.contains("editor_helper"));
    }

    /// Bundle casing is not the classifier's to assume.
    ///
    /// Real path observed on chain 2026-08-06 — `Claude` capitalised as the
    /// support directory, `claude.app` lowercase as the bundle. Against the
    /// keyword `Claude.app/` under case-sensitive matching this classified as
    /// unknown, so every Claude Code start was recorded as a security incident.
    #[test]
    fn benign_classification_is_case_insensitive_on_bundle_name() {
        let sen = Sentinel::new();
        let context = json!({
            "binary_path": "/Users/kenrom/Library/Application Support/Claude/claude-code/2.1.219/claude.app/Contents/MacOS/claude",
            "user": "kenrom",
            "parent_name": "zsh"
        });
        let ports = vec![json!({"port": 61234, "protocol": "TCP", "socket": "127.0.0.1:61234"})];

        let findings = sen.assess_unauthorized_listener(12345, "claude", &ports, &context);
        assert_eq!(findings[0].finding_type, "unregistered_known_app");
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].summary.contains("ai_client_helper"));
    }

    /// Ollama spawns a `llama-server` per model load on a random high port, so
    /// it is a recurring source of genuinely-new listeners that edge-triggering
    /// cannot suppress — each really is a new process.
    #[test]
    fn ollama_inference_backend_classifies_benign() {
        let sen = Sentinel::new();
        let context = json!({
            "binary_path": "/Applications/Ollama.app/Contents/Resources/llama-server",
            "user": "kenrom",
            "parent_name": "Ollama"
        });
        let ports = vec![json!({"port": 60546, "protocol": "TCP", "socket": "127.0.0.1:60546"})];

        let findings = sen.assess_unauthorized_listener(60546, "llama-server", &ports, &context);
        assert_eq!(findings[0].finding_type, "unregistered_known_app");
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].summary.contains("inference_backend"));
    }

    #[test]
    fn sentinel_classifies_messaging_helper_as_benign() {
        let sen = Sentinel::new();
        let context = json!({
            "pid": 73490,
            "name": "Signal Helper (Renderer)",
            "binary_path": "/Applications/Signal.app/Contents/Frameworks/Signal Helper (Renderer).app/Contents/MacOS/Signal Helper (Renderer)",
            "user": "ken",
            "parent_name": "Signal"
        });
        let ports = vec![json!({"port": 53219, "protocol": "TCP", "socket": "127.0.0.1:53219"})];

        let findings =
            sen.assess_unauthorized_listener(73490, "Signal Helper (Renderer)", &ports, &context);
        assert_eq!(findings[0].finding_type, "unregistered_known_app");
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].summary.contains("messaging_helper"));
    }

    #[test]
    fn sentinel_classifies_system_daemon_as_benign() {
        let sen = Sentinel::new();
        let context = json!({
            "pid": 1083,
            "name": "sharingd",
            "binary_path": "/usr/libexec/sharingd",
            "user": "ken",
            "parent_name": "launchd"
        });
        let ports = vec![json!({"port": 8770, "protocol": "TCP", "socket": "0.0.0.0:8770"})];

        let findings = sen.assess_unauthorized_listener(1083, "sharingd", &ports, &context);
        assert_eq!(findings[0].finding_type, "unregistered_known_app");
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].summary.contains("system_daemon"));
    }

    #[test]
    fn sentinel_still_flags_genuine_unknown_after_classifier() {
        // Genuinely unknown binary at a non-standard path should still get
        // the full risk assessment (not downgraded to Info).
        let sen = Sentinel::new();
        let context = json!({
            "pid": 45332,
            "name": "python3",
            "binary_path": "/tmp/suspicious/python3",
            "user": "ken",
            "parent_name": "unknown_wrapper"
        });
        let ports = vec![json!({"port": 8000, "protocol": "TCP", "socket": "0.0.0.0:8000"})];

        let findings = sen.assess_unauthorized_listener(45332, "python3", &ports, &context);
        assert_eq!(findings[0].finding_type, "unauthorized_listener");
        // Non-standard path + network-exposed → Error severity per Stage 2
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn sentinel_classifier_does_not_match_partial_paths() {
        // Ensure classifier doesn't false-match on similar-looking paths.
        // "/tmp/fake/Comet-not-really/binary" should NOT be classified as
        // benign browser helper.
        let sen = Sentinel::new();
        let context = json!({
            "pid": 99999,
            "name": "fake",
            "binary_path": "/tmp/fake/Comet-not-really/binary",
            "user": "ken",
            "parent_name": "zsh"
        });
        let ports = vec![json!({"port": 9999, "protocol": "TCP", "socket": "127.0.0.1:9999"})];

        let findings = sen.assess_unauthorized_listener(99999, "fake", &ports, &context);
        // Should NOT match — "Comet.app/" with trailing slash is the pattern
        assert_eq!(findings[0].finding_type, "unauthorized_listener");
    }

    #[test]
    fn sentinel_escalates_root_listener() {
        let sen = Sentinel::new();
        let context = json!({
            "pid": 999,
            "name": "rogue",
            "binary_path": "/tmp/rogue",
            "user": "root",
            "parent_name": "bash"
        });
        let ports = vec![json!({"port": 4444, "protocol": "TCP", "socket": "127.0.0.1:4444"})];

        let findings = sen.assess_unauthorized_listener(999, "rogue", &ports, &context);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].summary.contains("running as root"));
    }

    #[test]
    fn sentinel_escalates_network_exposed() {
        let sen = Sentinel::new();
        let context = json!({
            "pid": 555,
            "name": "server",
            "binary_path": "/usr/bin/python3",
            "user": "ken",
            "parent_name": "zsh"
        });
        let ports = vec![json!({"port": 8000, "protocol": "TCP", "socket": "0.0.0.0:8000"})];

        let findings = sen.assess_unauthorized_listener(555, "server", &ports, &context);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].summary.contains("network-exposed"));
    }

    #[test]
    fn sentinel_flags_unusual_parent() {
        let sen = Sentinel::new();
        let context = json!({
            "pid": 777,
            "name": "child",
            "binary_path": "/usr/bin/child",
            "user": "ken",
            "parent_name": "cryptominer"
        });
        let ports = vec![json!({"port": 9999, "protocol": "TCP", "socket": "127.0.0.1:9999"})];

        let findings = sen.assess_unauthorized_listener(777, "child", &ports, &context);
        assert!(findings[0].summary.contains("unusual parent"));
    }

    #[test]
    fn finding_event_key_format() {
        let f = Finding {
            officer: "sen",
            domain: "security",
            finding_type: "denial_cluster".into(),
            severity: Severity::Warning,
            summary: "test".into(),
            detail: json!({}),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        };

        assert_eq!(f.event_key(), "officer:sen:security:denial_cluster");
    }
}
