//! WASM policy module runtime — loads and executes policy rules compiled to WebAssembly.
//!
//! Each WASM policy module must export these functions:
//!
//! ```text
//! name_ptr()  -> i32    — pointer to UTF-8 module name in linear memory
//! name_len()  -> i32    — byte length of the module name
//! alloc(i32)  -> i32    — allocate n bytes of guest memory, return pointer
//! evaluate(i32, i32) -> i32  — evaluate(ctx_ptr, ctx_len) -> result_ptr
//! evaluate_len()     -> i32  — byte length of the last evaluate result
//! memory             — exported linear memory
//! ```
//!
//! The host serializes a `PolicyContext` as JSON, writes it into guest memory
//! via `alloc`, then calls `evaluate`. The guest returns a pointer to a
//! JSON-serialized `PolicyDecision` (or null/empty for "no opinion").
//!
//! This ABI is intentionally simple — JSON over shared memory — because
//! policy evaluation is not on the hot path and correctness matters more
//! than nanoseconds.

use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use wasmtime::*;

use zp_core::policy::{PolicyContext, PolicyDecision};

use crate::rules::PolicyRule;

/// Errors specific to the WASM policy runtime.
#[derive(Debug, thiserror::Error)]
pub enum WasmPolicyError {
    #[error("WASM compilation failed: {0}")]
    Compilation(String),
    #[error("WASM instantiation failed: {0}")]
    Instantiation(String),
    #[error("Missing required export: {0}")]
    MissingExport(String),
    #[error("Memory access error: {0}")]
    MemoryAccess(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Guest returned invalid UTF-8: {0}")]
    InvalidUtf8(String),
    #[error("Runtime error: {0}")]
    Runtime(String),
}

/// Metadata about a loaded WASM policy module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmModuleMetadata {
    /// Human-readable name (from the module's `name_ptr`/`name_len` exports).
    pub name: String,
    /// Blake3 hash of the WASM bytes — used for integrity verification.
    pub content_hash: String,
    /// Size of the WASM bytes in bytes.
    pub size_bytes: usize,
}

/// The WASM policy runtime — manages a wasmtime Engine and compiles modules.
///
/// A single WasmRuntime can be shared across threads. Each loaded module
/// gets its own Store and Instance.
pub struct WasmRuntime {
    engine: Engine,
}

impl WasmRuntime {
    /// Create a new WASM runtime with default configuration.
    pub fn new() -> Result<Self, WasmPolicyError> {
        let mut config = Config::new();
        // Fuel-based execution limits prevent infinite loops in guest modules
        config.consume_fuel(true);
        // Disable WASM features we don't need for policy modules
        config.wasm_threads(false);

        let engine =
            Engine::new(&config).map_err(|e| WasmPolicyError::Compilation(e.to_string()))?;

        Ok(Self { engine })
    }

    /// Load a WASM policy module from bytes (binary .wasm or text .wat).
    ///
    /// Returns a `WasmPolicyModule` that implements `PolicyRule`.
    pub fn load_module(&self, wasm_bytes: &[u8]) -> Result<WasmPolicyModule, WasmPolicyError> {
        // Compute content hash for integrity tracking
        let content_hash = blake3::hash(wasm_bytes).to_hex().to_string();
        let size_bytes = wasm_bytes.len();

        // Compile the module
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| WasmPolicyError::Compilation(e.to_string()))?;

        // Create a store with fuel limit (1_000_000 instructions per evaluation)
        let mut store = Store::new(&self.engine, ());
        store
            .set_fuel(1_000_000)
            .map_err(|e| WasmPolicyError::Runtime(e.to_string()))?;

        // Instantiate
        let instance = Instance::new(&mut store, &module, &[])
            .map_err(|e| WasmPolicyError::Instantiation(e.to_string()))?;

        // Verify required exports exist
        Self::verify_exports(&mut store, &instance)?;

        // Read the module name from guest memory
        let name = Self::read_module_name(&mut store, &instance)?;

        let metadata = WasmModuleMetadata {
            name: name.clone(),
            content_hash,
            size_bytes,
        };

        Ok(WasmPolicyModule {
            name,
            metadata,
            engine: self.engine.clone(),
            module,
            store: Arc::new(Mutex::new(store)),
            instance,
        })
    }

    /// Verify that the module exports all required functions.
    fn verify_exports(store: &mut Store<()>, instance: &Instance) -> Result<(), WasmPolicyError> {
        let required = ["name_ptr", "name_len", "alloc", "evaluate", "evaluate_len"];

        for name in &required {
            instance
                .get_func(&mut *store, name)
                .ok_or_else(|| WasmPolicyError::MissingExport(name.to_string()))?;
        }

        instance
            .get_memory(&mut *store, "memory")
            .ok_or_else(|| WasmPolicyError::MissingExport("memory".to_string()))?;

        Ok(())
    }

    /// Read the module name from guest memory via name_ptr/name_len.
    fn read_module_name(
        store: &mut Store<()>,
        instance: &Instance,
    ) -> Result<String, WasmPolicyError> {
        let name_ptr_fn = instance
            .get_typed_func::<(), i32>(&mut *store, "name_ptr")
            .map_err(|e| WasmPolicyError::MissingExport(format!("name_ptr: {}", e)))?;
        let name_len_fn = instance
            .get_typed_func::<(), i32>(&mut *store, "name_len")
            .map_err(|e| WasmPolicyError::MissingExport(format!("name_len: {}", e)))?;

        let ptr = name_ptr_fn
            .call(&mut *store, ())
            .map_err(|e| WasmPolicyError::Runtime(e.to_string()))? as usize;
        let len = name_len_fn
            .call(&mut *store, ())
            .map_err(|e| WasmPolicyError::Runtime(e.to_string()))? as usize;

        let memory = instance
            .get_memory(&mut *store, "memory")
            .ok_or_else(|| WasmPolicyError::MissingExport("memory".to_string()))?;

        let data = memory.data(&*store);
        if ptr + len > data.len() {
            return Err(WasmPolicyError::MemoryAccess(format!(
                "name_ptr={} name_len={} exceeds memory size {}",
                ptr,
                len,
                data.len()
            )));
        }

        let name_bytes = &data[ptr..ptr + len];
        String::from_utf8(name_bytes.to_vec())
            .map_err(|e| WasmPolicyError::InvalidUtf8(e.to_string()))
    }
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new().expect("Failed to create default WasmRuntime")
    }
}

/// A WASM-based policy module that implements the PolicyRule trait.
///
/// Wraps a compiled wasmtime module and manages the host↔guest memory protocol.
pub struct WasmPolicyModule {
    /// Cached module name (read once at load time).
    name: String,
    /// Module metadata (hash, size, etc.).
    pub metadata: WasmModuleMetadata,
    /// The wasmtime engine (shared).
    engine: Engine,
    /// The compiled module (can be re-instantiated for fresh state).
    module: Module,
    /// The store (holds runtime state). Mutex for Send+Sync.
    store: Arc<Mutex<Store<()>>>,
    /// The instance (live module with memory).
    instance: Instance,
}

impl WasmPolicyModule {
    /// Evaluate a PolicyContext through the WASM module.
    ///
    /// Serializes the context as JSON, passes it to the guest, and
    /// deserializes the result.
    fn evaluate_wasm(
        &self,
        context: &PolicyContext,
    ) -> Result<Option<PolicyDecision>, WasmPolicyError> {
        let mut store = self.store.lock();

        // Re-add fuel for this evaluation
        let remaining = store.get_fuel().unwrap_or(0);
        if remaining < 500_000 {
            store
                .set_fuel(1_000_000)
                .map_err(|e| WasmPolicyError::Runtime(e.to_string()))?;
        }

        // Serialize context to JSON
        let ctx_json = serde_json::to_vec(context)
            .map_err(|e| WasmPolicyError::Serialization(e.to_string()))?;
        let ctx_len = ctx_json.len() as i32;

        // Allocate guest memory for the context
        let alloc_fn = self
            .instance
            .get_typed_func::<i32, i32>(&mut *store, "alloc")
            .map_err(|e| WasmPolicyError::MissingExport(format!("alloc: {}", e)))?;

        let ctx_ptr = alloc_fn
            .call(&mut *store, ctx_len)
            .map_err(|e| WasmPolicyError::Runtime(e.to_string()))?;

        // Write context JSON into guest memory
        let memory = self
            .instance
            .get_memory(&mut *store, "memory")
            .ok_or_else(|| WasmPolicyError::MissingExport("memory".to_string()))?;

        memory
            .write(&mut *store, ctx_ptr as usize, &ctx_json)
            .map_err(|e| WasmPolicyError::MemoryAccess(e.to_string()))?;

        // Call evaluate(ctx_ptr, ctx_len) -> result_ptr
        let evaluate_fn = self
            .instance
            .get_typed_func::<(i32, i32), i32>(&mut *store, "evaluate")
            .map_err(|e| WasmPolicyError::MissingExport(format!("evaluate: {}", e)))?;

        let result_ptr = evaluate_fn
            .call(&mut *store, (ctx_ptr, ctx_len))
            .map_err(|e| WasmPolicyError::Runtime(e.to_string()))?;

        // A null pointer (0) means "no opinion" — the module doesn't apply
        if result_ptr == 0 {
            return Ok(None);
        }

        // Read result length
        let result_len_fn = self
            .instance
            .get_typed_func::<(), i32>(&mut *store, "evaluate_len")
            .map_err(|e| WasmPolicyError::MissingExport(format!("evaluate_len: {}", e)))?;

        let result_len = result_len_fn
            .call(&mut *store, ())
            .map_err(|e| WasmPolicyError::Runtime(e.to_string()))?
            as usize;

        if result_len == 0 {
            return Ok(None);
        }

        // Read result JSON from guest memory
        let data = memory.data(&*store);
        let rp = result_ptr as usize;
        if rp + result_len > data.len() {
            return Err(WasmPolicyError::MemoryAccess(format!(
                "result_ptr={} result_len={} exceeds memory size {}",
                rp,
                result_len,
                data.len()
            )));
        }

        let result_bytes = &data[rp..rp + result_len];
        let decision: PolicyDecision = serde_json::from_slice(result_bytes)
            .map_err(|e| WasmPolicyError::Serialization(format!("result parse: {}", e)))?;

        Ok(Some(decision))
    }

    /// Re-instantiate the module with fresh state.
    ///
    /// Useful if a module's internal state becomes corrupted or if
    /// fuel is exhausted.
    pub fn reset(&mut self) -> Result<(), WasmPolicyError> {
        let mut store = Store::new(&self.engine, ());
        store
            .set_fuel(1_000_000)
            .map_err(|e| WasmPolicyError::Runtime(e.to_string()))?;

        let instance = Instance::new(&mut store, &self.module, &[])
            .map_err(|e| WasmPolicyError::Instantiation(e.to_string()))?;

        self.store = Arc::new(Mutex::new(store));
        self.instance = instance;
        Ok(())
    }
}

/// WASM modules implement PolicyRule so they can be plugged directly
/// into the PolicyEngine alongside native Rust rules.
impl PolicyRule for WasmPolicyModule {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, context: &PolicyContext) -> Option<PolicyDecision> {
        match self.evaluate_wasm(context) {
            Ok(decision) => decision,
            Err(e) => {
                // WASM module errors are treated as "no opinion" with a warning.
                // We never let a broken WASM module block the pipeline.
                tracing::warn!(
                    module = %self.name,
                    error = %e,
                    "WASM policy module error — treating as no opinion"
                );
                None
            }
        }
    }
}

// Safety: WasmPolicyModule uses Arc<Mutex<Store>> for thread safety.
// The wasmtime Engine is Send+Sync, Module is Send+Sync, Instance is Send.
unsafe impl Send for WasmPolicyModule {}
unsafe impl Sync for WasmPolicyModule {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal WAT module that implements the policy ABI.
    /// Always returns an "Allow" decision with a condition string.
    const TEST_MODULE_WAT: &str = r#"
        (module
            (memory (export "memory") 1)

            ;; Data: module name "TestWasmRule" at offset 0 (12 bytes)
            (data (i32.const 0) "TestWasmRule")

            ;; Data: fixed Allow result JSON at offset 64
            ;; {"Allow":{"conditions":["wasm_policy_allowed"]}}
            (data (i32.const 64) "{\"Allow\":{\"conditions\":[\"wasm_policy_allowed\"]}}")

            ;; Bump allocator pointer starts at 1024
            (global $bump (mut i32) (i32.const 1024))

            (func (export "name_ptr") (result i32)
                i32.const 0
            )

            (func (export "name_len") (result i32)
                i32.const 12
            )

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
                ;; Ignore input, always return pointer to fixed Allow JSON
                i32.const 64
            )

            (func (export "evaluate_len") (result i32)
                ;; Length of the fixed JSON string
                i32.const 48
            )
        )
    "#;

    /// WAT module that returns null (no opinion) for every evaluation.
    const NULL_MODULE_WAT: &str = r#"
        (module
            (memory (export "memory") 1)
            (data (i32.const 0) "NullRule")
            (global $bump (mut i32) (i32.const 1024))

            (func (export "name_ptr") (result i32) i32.const 0)
            (func (export "name_len") (result i32) i32.const 8)
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
                i32.const 0
            )
            (func (export "evaluate_len") (result i32) i32.const 0)
        )
    "#;

    /// WAT module that always blocks with a reason.
    /// JSON: {"Block":{"reason":"no","policy_module":"BAll"}}
    /// Length: 42 (framework) + 2 ("no") + 4 ("BAll") = 48
    const BLOCK_MODULE_WAT: &str = r#"
        (module
            (memory (export "memory") 1)
            (data (i32.const 0) "BlockAllRule")
            (data (i32.const 64) "{\"Block\":{\"reason\":\"no\",\"policy_module\":\"BAll\"}}")
            (global $bump (mut i32) (i32.const 1024))

            (func (export "name_ptr") (result i32) i32.const 0)
            (func (export "name_len") (result i32) i32.const 12)
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

    fn make_test_context() -> PolicyContext {
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
    fn test_runtime_creation() {
        let runtime = WasmRuntime::new();
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_load_module() {
        let runtime = WasmRuntime::new().unwrap();
        let module = runtime.load_module(TEST_MODULE_WAT.as_bytes());
        assert!(module.is_ok());
        let module = module.unwrap();
        assert_eq!(module.name, "TestWasmRule");
        assert_eq!(module.metadata.name, "TestWasmRule");
        assert!(module.metadata.size_bytes > 0);
        assert!(!module.metadata.content_hash.is_empty());
    }

    #[test]
    fn test_evaluate_returns_allow() {
        let runtime = WasmRuntime::new().unwrap();
        let module = runtime.load_module(TEST_MODULE_WAT.as_bytes()).unwrap();
        let context = make_test_context();

        let decision = module.evaluate(&context);
        assert!(decision.is_some());
        assert!(
            matches!(decision, Some(PolicyDecision::Allow { .. })),
            "Expected Allow, got {:?}",
            decision
        );
    }

    #[test]
    fn test_null_module_returns_none() {
        let runtime = WasmRuntime::new().unwrap();
        let module = runtime.load_module(NULL_MODULE_WAT.as_bytes()).unwrap();
        let context = make_test_context();

        let decision = module.evaluate(&context);
        assert!(decision.is_none());
    }

    #[test]
    fn test_block_module_returns_block() {
        let runtime = WasmRuntime::new().unwrap();
        let module = runtime.load_module(BLOCK_MODULE_WAT.as_bytes()).unwrap();
        let context = make_test_context();

        // First verify the JSON format round-trips correctly in serde
        let test_json = r#"{"Block":{"reason":"no","policy_module":"BAll"}}"#;
        assert_eq!(test_json.len(), 48, "JSON length sanity check");
        let _: PolicyDecision = serde_json::from_str(test_json).unwrap();

        let result = module.evaluate_wasm(&context);
        match &result {
            Err(e) => panic!("evaluate_wasm error: {}", e),
            Ok(None) => panic!("evaluate_wasm returned None"),
            Ok(Some(_)) => {}
        }

        let decision = result.unwrap();
        match decision {
            Some(PolicyDecision::Block {
                reason,
                policy_module,
            }) => {
                assert_eq!(reason, "no");
                assert_eq!(policy_module, "BAll");
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_policy_rule_trait_name() {
        let runtime = WasmRuntime::new().unwrap();
        let module = runtime.load_module(TEST_MODULE_WAT.as_bytes()).unwrap();

        // PolicyRule::name() should return the WASM module's exported name
        let rule: &dyn PolicyRule = &module;
        assert_eq!(rule.name(), "TestWasmRule");
    }

    #[test]
    fn test_module_metadata_hash() {
        let runtime = WasmRuntime::new().unwrap();
        let m1 = runtime.load_module(TEST_MODULE_WAT.as_bytes()).unwrap();
        let m2 = runtime.load_module(TEST_MODULE_WAT.as_bytes()).unwrap();

        // Same bytes → same hash
        assert_eq!(m1.metadata.content_hash, m2.metadata.content_hash);

        // Different bytes → different hash
        let m3 = runtime.load_module(NULL_MODULE_WAT.as_bytes()).unwrap();
        assert_ne!(m1.metadata.content_hash, m3.metadata.content_hash);
    }

    #[test]
    fn test_missing_export_rejected() {
        let runtime = WasmRuntime::new().unwrap();
        // Minimal module with no exports
        let bad_wat = r#"(module (memory 1))"#;
        let result = runtime.load_module(bad_wat.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_module_reset() {
        let runtime = WasmRuntime::new().unwrap();
        let mut module = runtime.load_module(TEST_MODULE_WAT.as_bytes()).unwrap();
        let context = make_test_context();

        // Evaluate, then reset, then evaluate again
        let d1 = module.evaluate(&context);
        assert!(d1.is_some());

        module.reset().unwrap();

        let d2 = module.evaluate(&context);
        assert!(d2.is_some());
    }

    #[test]
    fn test_multiple_evaluations() {
        let runtime = WasmRuntime::new().unwrap();
        let module = runtime.load_module(TEST_MODULE_WAT.as_bytes()).unwrap();

        // Run 50 evaluations in sequence — fuel should be replenished
        for i in 0..50 {
            let context = make_test_context();
            let decision = module.evaluate(&context);
            assert!(decision.is_some(), "Evaluation {} should return Some", i);
        }
    }
}
