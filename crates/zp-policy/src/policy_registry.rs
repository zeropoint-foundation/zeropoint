//! Policy module registry — manages loading, lifecycle, and lookup of WASM policy modules.
//!
//! The registry is the single source of truth for which WASM policy modules are
//! currently active. It handles:
//!
//! - **Loading**: Compile WASM bytes, verify exports, register the module
//! - **Integrity**: Track content hashes so modules can be verified against
//!   a known-good manifest (e.g., signed by a governance key)
//! - **Enable/disable**: Modules can be toggled without unloading
//! - **Priority ordering**: Modules evaluate in registration order;
//!   constitutional rules always evaluate first (enforced by the engine)
//! - **Thread safety**: The registry is `Send + Sync` via `parking_lot::RwLock`
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │  PolicyEngine                                     │
//! │  ┌─────────────────┐  ┌────────────────────────┐ │
//! │  │  Native Rules   │  │  PolicyModuleRegistry  │ │
//! │  │  (constitutional │  │  ┌──────────────────┐  │ │
//! │  │   + operational) │  │  │ WasmPolicyModule │  │ │
//! │  │                  │  │  │ WasmPolicyModule │  │ │
//! │  │                  │  │  │ WasmPolicyModule │  │ │
//! │  └─────────────────┘  │  └──────────────────┘  │ │
//! │                        └────────────────────────┘ │
//! └──────────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::rules::PolicyRule;
use crate::wasm_runtime::{WasmModuleMetadata, WasmPolicyError, WasmPolicyModule, WasmRuntime};
use zp_core::policy::{PolicyContext, PolicyDecision};

/// Status of a registered policy module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleStatus {
    /// Module is active and will be evaluated.
    Active,
    /// Module is loaded but temporarily disabled.
    Disabled,
    /// Module failed to load or encountered a fatal error.
    Error(String),
}

/// A registered module entry in the registry.
struct RegisteredModule {
    /// The live WASM policy module.
    module: WasmPolicyModule,
    /// Current status.
    status: ModuleStatus,
    /// Registration order (lower = earlier evaluation).
    priority: usize,
    /// Original WASM bytes (retained for mesh transfer to peers).
    wasm_bytes: Vec<u8>,
}

/// The policy module registry.
///
/// Manages the lifecycle of WASM policy modules. Thread-safe via RwLock.
pub struct PolicyModuleRegistry {
    /// The shared WASM runtime (engine).
    runtime: WasmRuntime,
    /// Registered modules keyed by content hash.
    modules: RwLock<HashMap<String, RegisteredModule>>,
    /// Next priority counter.
    next_priority: RwLock<usize>,
}

impl PolicyModuleRegistry {
    /// Create a new empty registry.
    pub fn new() -> Result<Self, WasmPolicyError> {
        Ok(Self {
            runtime: WasmRuntime::new()?,
            modules: RwLock::new(HashMap::new()),
            next_priority: RwLock::new(0),
        })
    }

    /// Create a registry with an existing WasmRuntime.
    pub fn with_runtime(runtime: WasmRuntime) -> Self {
        Self {
            runtime,
            modules: RwLock::new(HashMap::new()),
            next_priority: RwLock::new(0),
        }
    }

    /// Load and register a WASM policy module from bytes.
    ///
    /// Returns the module's content hash (used as its registry key)
    /// and metadata.
    pub fn load(&self, wasm_bytes: &[u8]) -> Result<WasmModuleMetadata, WasmPolicyError> {
        let module = self.runtime.load_module(wasm_bytes)?;
        let metadata = module.metadata.clone();
        let hash = metadata.content_hash.clone();

        let mut priority = self.next_priority.write();
        let entry = RegisteredModule {
            module,
            status: ModuleStatus::Active,
            priority: *priority,
            wasm_bytes: wasm_bytes.to_vec(),
        };
        *priority += 1;

        self.modules.write().insert(hash, entry);
        Ok(metadata)
    }

    /// Unload a module by its content hash.
    ///
    /// Returns true if the module was found and removed.
    pub fn unload(&self, content_hash: &str) -> bool {
        self.modules.write().remove(content_hash).is_some()
    }

    /// Enable a previously disabled module.
    pub fn enable(&self, content_hash: &str) -> bool {
        let mut modules = self.modules.write();
        if let Some(entry) = modules.get_mut(content_hash) {
            entry.status = ModuleStatus::Active;
            true
        } else {
            false
        }
    }

    /// Disable a module without unloading it.
    pub fn disable(&self, content_hash: &str) -> bool {
        let mut modules = self.modules.write();
        if let Some(entry) = modules.get_mut(content_hash) {
            entry.status = ModuleStatus::Disabled;
            true
        } else {
            false
        }
    }

    /// Get the status of a module.
    pub fn status(&self, content_hash: &str) -> Option<ModuleStatus> {
        self.modules
            .read()
            .get(content_hash)
            .map(|e| e.status.clone())
    }

    /// Get metadata for a module.
    pub fn metadata(&self, content_hash: &str) -> Option<WasmModuleMetadata> {
        self.modules
            .read()
            .get(content_hash)
            .map(|e| e.module.metadata.clone())
    }

    /// List all registered module metadata and statuses.
    pub fn list(&self) -> Vec<(WasmModuleMetadata, ModuleStatus)> {
        let modules = self.modules.read();
        let mut entries: Vec<_> = modules
            .values()
            .map(|e| (e.module.metadata.clone(), e.status.clone(), e.priority))
            .collect();
        entries.sort_by_key(|(_, _, p)| *p);
        entries
            .into_iter()
            .map(|(meta, status, _)| (meta, status))
            .collect()
    }

    /// Number of registered modules (active + disabled).
    pub fn count(&self) -> usize {
        self.modules.read().len()
    }

    /// Number of active modules.
    pub fn active_count(&self) -> usize {
        self.modules
            .read()
            .values()
            .filter(|e| e.status == ModuleStatus::Active)
            .count()
    }

    /// Evaluate all active WASM modules against a policy context.
    ///
    /// Returns a vector of (module_name, decision) pairs for modules
    /// that returned a decision. Modules are evaluated in priority order.
    pub fn evaluate_all(&self, context: &PolicyContext) -> Vec<(String, PolicyDecision)> {
        let modules = self.modules.read();

        // Sort by priority
        let mut active: Vec<_> = modules
            .values()
            .filter(|e| e.status == ModuleStatus::Active)
            .collect();
        active.sort_by_key(|e| e.priority);

        let mut results = Vec::new();
        for entry in active {
            if let Some(decision) = entry.module.evaluate(context) {
                results.push((entry.module.metadata.name.clone(), decision));
            }
        }
        results
    }

    // --- Mesh sync support (Phase 3) ---

    /// Get advertisement info for all active modules.
    ///
    /// Returns metadata suitable for broadcasting to mesh peers.
    pub fn advertise(&self, default_min_tier: u8) -> Vec<(String, String, usize, u8)> {
        let modules = self.modules.read();
        modules
            .values()
            .filter(|e| e.status == ModuleStatus::Active)
            .map(|e| {
                (
                    e.module.metadata.name.clone(),
                    e.module.metadata.content_hash.clone(),
                    e.module.metadata.size_bytes,
                    default_min_tier,
                )
            })
            .collect()
    }

    /// Get the raw WASM bytes for a module by content hash.
    ///
    /// Used when transferring a module to a peer over the mesh.
    pub fn get_module_bytes(&self, content_hash: &str) -> Option<Vec<u8>> {
        self.modules
            .read()
            .get(content_hash)
            .map(|e| e.wasm_bytes.clone())
    }

    /// Load a module received from a peer, verifying its hash matches.
    ///
    /// Returns Err if the hash doesn't match or if the module is invalid.
    pub fn load_from_peer(
        &self,
        wasm_bytes: &[u8],
        expected_hash: &str,
    ) -> Result<WasmModuleMetadata, WasmPolicyError> {
        // Verify hash first
        let actual_hash = blake3::hash(wasm_bytes).to_hex().to_string();
        if actual_hash != expected_hash {
            return Err(WasmPolicyError::Compilation(format!(
                "hash mismatch: expected {}, got {}",
                expected_hash, actual_hash
            )));
        }
        // Delegate to normal load
        self.load(wasm_bytes)
    }

    /// Verify that all registered modules match their recorded content hashes.
    ///
    /// This is a defensive check — if a module's hash doesn't match its
    /// registry key, something has gone wrong (memory corruption, etc.).
    pub fn verify_integrity(&self) -> Vec<(String, bool)> {
        let modules = self.modules.read();
        modules
            .iter()
            .map(|(hash, entry)| {
                let matches = entry.module.metadata.content_hash == *hash;
                (hash.clone(), matches)
            })
            .collect()
    }

    /// Auto-discover and load all `.wasm` files from a directory.
    ///
    /// Scans the given directory for files with a `.wasm` extension,
    /// loads each one, and returns a summary of successes and failures.
    /// Files that fail to load are reported but do not prevent other
    /// modules from loading.
    ///
    /// This is the primary mechanism for operators to deploy custom
    /// policy modules: drop a `.wasm` file into `~/ZeroPoint/policies/`
    /// and the engine picks it up on next startup.
    pub fn load_directory(
        &self,
        dir: &std::path::Path,
    ) -> Vec<Result<(std::path::PathBuf, WasmModuleMetadata), (std::path::PathBuf, String)>> {
        let mut results = Vec::new();

        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::debug!("Could not read policy directory {:?}: {}", dir, e);
                return results;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
                continue;
            }

            match std::fs::read(&path) {
                Ok(bytes) => match self.load(&bytes) {
                    Ok(metadata) => {
                        tracing::info!(
                            "Loaded policy module '{}' from {:?} (hash: {})",
                            metadata.name,
                            path,
                            &metadata.content_hash[..8]
                        );
                        results.push(Ok((path, metadata)));
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load policy module {:?}: {}", path, e);
                        results.push(Err((path, e.to_string())));
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to read {:?}: {}", path, e);
                    results.push(Err((path, e.to_string())));
                }
            }
        }

        results
    }
}

impl Default for PolicyModuleRegistry {
    fn default() -> Self {
        Self::new().expect("Failed to create default PolicyModuleRegistry")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same test WAT from wasm_runtime tests — always returns Allow.
    const ALLOW_WAT: &str = r#"
        (module
            (memory (export "memory") 1)
            (data (i32.const 0) "AllowModule")
            (data (i32.const 64) "{\"Allow\":{\"conditions\":[\"wasm_allowed\"]}}")
            (global $bump (mut i32) (i32.const 1024))
            (func (export "name_ptr") (result i32) i32.const 0)
            (func (export "name_len") (result i32) i32.const 11)
            (func (export "alloc") (param $size i32) (result i32)
                (local $ptr i32)
                global.get $bump
                local.set $ptr
                global.get $bump
                local.get $size
                i32.add
                global.set $bump
                local.get $ptr
            )
            (func (export "evaluate") (param $ctx_ptr i32) (param $ctx_len i32) (result i32)
                i32.const 64
            )
            (func (export "evaluate_len") (result i32) i32.const 41)
        )
    "#;

    /// WAT module that blocks everything.
    /// JSON: {"Block":{"reason":"no","policy_module":"BReg"}}
    /// Length: 42 + 2 + 4 = 48
    const BLOCK_WAT: &str = r#"
        (module
            (memory (export "memory") 1)
            (data (i32.const 0) "BlockModule")
            (data (i32.const 64) "{\"Block\":{\"reason\":\"no\",\"policy_module\":\"BReg\"}}")
            (global $bump (mut i32) (i32.const 1024))
            (func (export "name_ptr") (result i32) i32.const 0)
            (func (export "name_len") (result i32) i32.const 11)
            (func (export "alloc") (param $size i32) (result i32)
                (local $ptr i32)
                global.get $bump
                local.set $ptr
                global.get $bump
                local.get $size
                i32.add
                global.set $bump
                local.get $ptr
            )
            (func (export "evaluate") (param $ctx_ptr i32) (param $ctx_len i32) (result i32)
                i32.const 64
            )
            (func (export "evaluate_len") (result i32) i32.const 48)
        )
    "#;

    fn make_context() -> PolicyContext {
        PolicyContext {
            action: zp_core::policy::ActionType::Chat,
            trust_tier: zp_core::policy::TrustTier::Tier0,
            channel: zp_core::Channel::Cli,
            conversation_id: zp_core::ConversationId::new(),
            skill_ids: vec![],
            tool_names: vec![],
            mesh_context: None,
        }
    }

    #[test]
    fn test_registry_creation() {
        let registry = PolicyModuleRegistry::new();
        assert!(registry.is_ok());
        assert_eq!(registry.unwrap().count(), 0);
    }

    #[test]
    fn test_load_module() {
        let registry = PolicyModuleRegistry::new().unwrap();
        let meta = registry.load(ALLOW_WAT.as_bytes());
        assert!(meta.is_ok());
        let meta = meta.unwrap();
        assert_eq!(meta.name, "AllowModule");
        assert_eq!(registry.count(), 1);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_load_multiple_modules() {
        let registry = PolicyModuleRegistry::new().unwrap();
        let m1 = registry.load(ALLOW_WAT.as_bytes()).unwrap();
        let m2 = registry.load(BLOCK_WAT.as_bytes()).unwrap();
        assert_eq!(registry.count(), 2);
        assert_ne!(m1.content_hash, m2.content_hash);
    }

    #[test]
    fn test_unload_module() {
        let registry = PolicyModuleRegistry::new().unwrap();
        let meta = registry.load(ALLOW_WAT.as_bytes()).unwrap();
        assert_eq!(registry.count(), 1);

        assert!(registry.unload(&meta.content_hash));
        assert_eq!(registry.count(), 0);

        // Double unload returns false
        assert!(!registry.unload(&meta.content_hash));
    }

    #[test]
    fn test_enable_disable() {
        let registry = PolicyModuleRegistry::new().unwrap();
        let meta = registry.load(ALLOW_WAT.as_bytes()).unwrap();

        assert_eq!(
            registry.status(&meta.content_hash),
            Some(ModuleStatus::Active)
        );
        assert_eq!(registry.active_count(), 1);

        registry.disable(&meta.content_hash);
        assert_eq!(
            registry.status(&meta.content_hash),
            Some(ModuleStatus::Disabled)
        );
        assert_eq!(registry.active_count(), 0);

        registry.enable(&meta.content_hash);
        assert_eq!(
            registry.status(&meta.content_hash),
            Some(ModuleStatus::Active)
        );
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_list_modules() {
        let registry = PolicyModuleRegistry::new().unwrap();
        registry.load(ALLOW_WAT.as_bytes()).unwrap();
        registry.load(BLOCK_WAT.as_bytes()).unwrap();

        let list = registry.list();
        assert_eq!(list.len(), 2);
        // First registered should have lower priority
        assert_eq!(list[0].0.name, "AllowModule");
        assert_eq!(list[1].0.name, "BlockModule");
    }

    #[test]
    fn test_evaluate_all_active_only() {
        let registry = PolicyModuleRegistry::new().unwrap();
        let m1 = registry.load(ALLOW_WAT.as_bytes()).unwrap();
        registry.load(BLOCK_WAT.as_bytes()).unwrap();

        let ctx = make_context();

        // Both active → 2 results
        let results = registry.evaluate_all(&ctx);
        assert_eq!(results.len(), 2);

        // Disable allow module → only block remains
        registry.disable(&m1.content_hash);
        let results = registry.evaluate_all(&ctx);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].1, PolicyDecision::Block { .. }));
    }

    #[test]
    fn test_evaluate_all_priority_order() {
        let registry = PolicyModuleRegistry::new().unwrap();
        // Load block first, then allow
        registry.load(BLOCK_WAT.as_bytes()).unwrap();
        registry.load(ALLOW_WAT.as_bytes()).unwrap();

        let ctx = make_context();
        let results = registry.evaluate_all(&ctx);
        assert_eq!(results.len(), 2);
        // Block was registered first → evaluated first
        assert_eq!(results[0].0, "BlockModule");
        assert_eq!(results[1].0, "AllowModule");
    }

    #[test]
    fn test_verify_integrity() {
        let registry = PolicyModuleRegistry::new().unwrap();
        registry.load(ALLOW_WAT.as_bytes()).unwrap();
        registry.load(BLOCK_WAT.as_bytes()).unwrap();

        let integrity = registry.verify_integrity();
        assert_eq!(integrity.len(), 2);
        for (_, valid) in &integrity {
            assert!(valid, "All modules should pass integrity check");
        }
    }

    #[test]
    fn test_metadata_lookup() {
        let registry = PolicyModuleRegistry::new().unwrap();
        let meta = registry.load(ALLOW_WAT.as_bytes()).unwrap();

        let looked_up = registry.metadata(&meta.content_hash);
        assert!(looked_up.is_some());
        let looked_up = looked_up.unwrap();
        assert_eq!(looked_up.name, meta.name);
        assert_eq!(looked_up.content_hash, meta.content_hash);
    }

    #[test]
    fn test_status_missing_module() {
        let registry = PolicyModuleRegistry::new().unwrap();
        assert!(registry.status("nonexistent").is_none());
    }

    #[test]
    fn test_enable_disable_missing() {
        let registry = PolicyModuleRegistry::new().unwrap();
        assert!(!registry.enable("nonexistent"));
        assert!(!registry.disable("nonexistent"));
    }

    // --- Mesh sync tests (Phase 3) ---

    #[test]
    fn test_advertise_returns_active_modules() {
        let registry = PolicyModuleRegistry::new().unwrap();
        let m1 = registry.load(ALLOW_WAT.as_bytes()).unwrap();
        registry.load(BLOCK_WAT.as_bytes()).unwrap();

        // Disable one
        registry.disable(&m1.content_hash);

        let ads = registry.advertise(0);
        // Only active modules advertised
        assert_eq!(ads.len(), 1);
        assert_eq!(ads[0].0, "BlockModule");
    }

    #[test]
    fn test_get_module_bytes_returns_wasm() {
        let registry = PolicyModuleRegistry::new().unwrap();
        let meta = registry.load(ALLOW_WAT.as_bytes()).unwrap();

        let bytes = registry.get_module_bytes(&meta.content_hash);
        assert!(bytes.is_some());
        let bytes = bytes.unwrap();
        assert_eq!(bytes, ALLOW_WAT.as_bytes());
    }

    #[test]
    fn test_get_module_bytes_missing() {
        let registry = PolicyModuleRegistry::new().unwrap();
        assert!(registry.get_module_bytes("nonexistent").is_none());
    }

    #[test]
    fn test_load_from_peer_verifies_hash() {
        let registry = PolicyModuleRegistry::new().unwrap();
        let wasm_bytes = ALLOW_WAT.as_bytes();
        let expected_hash = blake3::hash(wasm_bytes).to_hex().to_string();

        let meta = registry.load_from_peer(wasm_bytes, &expected_hash);
        assert!(meta.is_ok());
        assert_eq!(meta.unwrap().name, "AllowModule");
    }

    #[test]
    fn test_load_from_peer_rejects_tampered() {
        let registry = PolicyModuleRegistry::new().unwrap();
        let wasm_bytes = ALLOW_WAT.as_bytes();
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";

        let result = registry.load_from_peer(wasm_bytes, wrong_hash);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmPolicyError::Compilation(msg) => assert!(msg.contains("hash mismatch")),
            _ => panic!("Expected Compilation error, got {:?}", err),
        }
    }
}
