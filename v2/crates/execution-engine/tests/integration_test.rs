//! Integration tests for the ZeroPoint Deterministic Execution Engine.
//!
//! These tests verify the full execution pipeline:
//!   request → runtime detection → sandbox setup → code execution → receipt generation
//!
//! Tests run actual Python/Node/Shell commands via the engine, so they require
//! those runtimes to be installed on the host.

use execution_engine::{
    ExecutionEngine, ExecutionError, ExecutionRequest, Runtime, SandboxCapability, SandboxConfig,
};

// ============================================================================
// Engine Initialization
// ============================================================================

#[tokio::test]
#[ignore] // Requires Python/Node/Shell runtimes on host
async fn test_engine_creation_detects_runtimes() {
    let engine = ExecutionEngine::new().await.expect("engine init");
    let status = engine.status();

    // At minimum, we should detect Python (this test runs in a Python-capable env)
    assert!(
        status.runtimes.iter().any(|(rt, _)| *rt == Runtime::Python),
        "Engine should detect Python runtime. Detected: {:?}",
        status.runtimes
    );
}

#[tokio::test]
async fn test_engine_status_reports_available() {
    let engine = ExecutionEngine::new().await.expect("engine init");
    let status = engine.status();
    // Engine should always be available after construction
    assert!(status.available);
    assert!(status.total_executions == 0);
}

// ============================================================================
// Python Execution
// ============================================================================

#[tokio::test]
#[ignore] // Requires Python runtime on host
async fn test_execute_python_hello_world() {
    let engine = ExecutionEngine::new().await.expect("engine init");

    let request = ExecutionRequest {
        request_id: "test-py-hello".to_string(),
        runtime: Runtime::Python,
        code: "print('hello from zp engine')".to_string(),
        args: vec![],
        sandbox_override: None,
        agent_id: "test".to_string(),
        deployment_receipt_id: None,
    };

    let result = engine.execute(request).await;
    assert!(
        result.is_ok(),
        "Python hello world should succeed: {:?}",
        result.err()
    );

    let result = result.unwrap();
    assert!(result.success, "Exit should be successful");
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("hello from zp engine"),
        "stdout should contain our print output. Got: '{}'",
        result.stdout
    );
    assert!(result.stderr.is_empty() || result.stderr.trim().is_empty());

    // Verify receipt
    assert!(!result.receipt.receipt_id.is_nil());
    assert!(!result.receipt.input_hash.is_empty());
    assert!(!result.receipt.output_hash.is_empty());
    assert!(!result.receipt.receipt_hash.is_empty());
    assert_eq!(result.receipt.exit_code, 0);
    assert!(result.receipt.success);
}

#[tokio::test]
#[ignore] // Requires Python runtime on host
async fn test_execute_python_with_computation() {
    let engine = ExecutionEngine::new().await.expect("engine init");

    let request = ExecutionRequest {
        request_id: "test-py-compute".to_string(),
        runtime: Runtime::Python,
        code: "result = sum(range(100))\nprint(result)".to_string(),
        args: vec![],
        sandbox_override: None,
        agent_id: "test".to_string(),
        deployment_receipt_id: None,
    };

    let result = engine.execute(request).await.expect("Should succeed");
    assert_eq!(result.stdout.trim(), "4950");
    assert_eq!(result.exit_code, 0);
}

#[tokio::test]
#[ignore] // Requires Python runtime on host
async fn test_execute_python_with_error() {
    let engine = ExecutionEngine::new().await.expect("engine init");

    let request = ExecutionRequest {
        request_id: "test-py-error".to_string(),
        runtime: Runtime::Python,
        code: "raise ValueError('intentional test error')".to_string(),
        args: vec![],
        sandbox_override: None,
        agent_id: "test".to_string(),
        deployment_receipt_id: None,
    };

    let result = engine
        .execute(request)
        .await
        .expect("Should return a result even on error");
    assert!(!result.success, "Should report failure");
    assert_ne!(result.exit_code, 0);
    assert!(
        result.stderr.contains("ValueError") || result.stderr.contains("intentional test error"),
        "stderr should contain the error. Got: '{}'",
        result.stderr
    );

    // Receipt should still be generated
    assert!(!result.receipt.receipt_hash.is_empty());
    assert!(!result.receipt.success);
}

#[tokio::test]
#[ignore] // Requires Python runtime on host
async fn test_execute_python_multiline() {
    let engine = ExecutionEngine::new().await.expect("engine init");

    let code = r#"
import json

data = {"key": "value", "numbers": [1, 2, 3]}
print(json.dumps(data, sort_keys=True))
"#;

    let request = ExecutionRequest {
        request_id: "test-py-multiline".to_string(),
        runtime: Runtime::Python,
        code: code.to_string(),
        args: vec![],
        sandbox_override: None,
        agent_id: "test".to_string(),
        deployment_receipt_id: None,
    };

    let result = engine.execute(request).await.expect("Should succeed");
    let parsed: serde_json::Value =
        serde_json::from_str(result.stdout.trim()).expect("Output should be valid JSON");
    assert_eq!(parsed["key"], "value");
}

// ============================================================================
// Shell Execution
// ============================================================================

#[tokio::test]
#[ignore] // Requires Shell runtime on host
async fn test_execute_shell_echo() {
    let engine = ExecutionEngine::new().await.expect("engine init");

    // Skip if bash not available
    let status = engine.status();
    if !status.runtimes.iter().any(|(rt, _)| *rt == Runtime::Shell) {
        eprintln!("Skipping shell test — bash not detected");
        return;
    }

    let request = ExecutionRequest {
        request_id: "test-sh-echo".to_string(),
        runtime: Runtime::Shell,
        code: "echo 'hello from shell'".to_string(),
        args: vec![],
        sandbox_override: None,
        agent_id: "test".to_string(),
        deployment_receipt_id: None,
    };

    let result = engine.execute(request).await.expect("Should succeed");
    assert!(result.stdout.contains("hello from shell"));
    assert_eq!(result.exit_code, 0);
}

// ============================================================================
// Node.js Execution
// ============================================================================

#[tokio::test]
#[ignore] // Requires Node.js runtime on host
async fn test_execute_nodejs_hello() {
    let engine = ExecutionEngine::new().await.expect("engine init");

    let status = engine.status();
    if !status.runtimes.iter().any(|(rt, _)| *rt == Runtime::NodeJs) {
        eprintln!("Skipping Node.js test — node not detected");
        return;
    }

    let request = ExecutionRequest {
        request_id: "test-node-hello".to_string(),
        runtime: Runtime::NodeJs,
        code: "console.log('hello from node')".to_string(),
        args: vec![],
        sandbox_override: None,
        agent_id: "test".to_string(),
        deployment_receipt_id: None,
    };

    let result = engine.execute(request).await.expect("Should succeed");
    assert!(result.stdout.contains("hello from node"));
    assert_eq!(result.exit_code, 0);
}

// ============================================================================
// Receipt Verification
// ============================================================================

#[tokio::test]
#[ignore] // Requires Python runtime on host
async fn test_receipt_determinism() {
    // Same code should produce same input hash (but different receipt IDs)
    let engine = ExecutionEngine::new().await.expect("engine init");
    let code = "print('deterministic')".to_string();

    let req1 = ExecutionRequest {
        request_id: "det-1".to_string(),
        runtime: Runtime::Python,
        code: code.clone(),
        args: vec![],
        sandbox_override: None,
        agent_id: "test".to_string(),
        deployment_receipt_id: None,
    };

    let req2 = ExecutionRequest {
        request_id: "det-2".to_string(),
        runtime: Runtime::Python,
        code: code.clone(),
        args: vec![],
        sandbox_override: None,
        agent_id: "test".to_string(),
        deployment_receipt_id: None,
    };

    let r1 = engine.execute(req1).await.expect("r1");
    let r2 = engine.execute(req2).await.expect("r2");

    // Input hashes should be identical (same code + args)
    assert_eq!(
        r1.receipt.input_hash, r2.receipt.input_hash,
        "Same code should produce same input hash"
    );

    // Output hashes should be identical (deterministic code)
    assert_eq!(
        r1.receipt.output_hash, r2.receipt.output_hash,
        "Deterministic code should produce same output hash"
    );

    // Receipt IDs should be different (unique per execution)
    assert_ne!(r1.receipt.receipt_id, r2.receipt.receipt_id);
}

// ============================================================================
// Sandbox Limits
// ============================================================================

#[tokio::test]
#[ignore] // Requires Python runtime on host
async fn test_execution_timeout() {
    let engine = ExecutionEngine::new().await.expect("engine init");

    let mut sandbox = SandboxConfig::default();
    sandbox.timeout_ms = 2_000; // 2 second timeout

    let request = ExecutionRequest {
        request_id: "test-timeout".to_string(),
        runtime: Runtime::Python,
        code: "import time; time.sleep(30)".to_string(),
        args: vec![],
        sandbox_override: Some(sandbox),
        agent_id: "test".to_string(),
        deployment_receipt_id: None,
    };

    let result = engine.execute(request).await;
    // Should either timeout (Err) or return with timed_out flag
    match result {
        Ok(r) => {
            assert!(
                r.timed_out || !r.success,
                "Should indicate timeout or failure"
            );
        }
        Err(ExecutionError::Timeout(_)) => {
            // Expected
        }
        Err(e) => {
            // Other errors are acceptable (process killed, etc.)
            eprintln!("Timeout test got error (acceptable): {:?}", e);
        }
    }
}

#[tokio::test]
#[ignore] // Requires Python runtime on host
async fn test_output_limit() {
    let engine = ExecutionEngine::new().await.expect("engine init");

    let mut sandbox = SandboxConfig::default();
    sandbox.max_output_bytes = 100; // Very small output limit

    let request = ExecutionRequest {
        request_id: "test-output-limit".to_string(),
        runtime: Runtime::Python,
        code: "print('x' * 10000)".to_string(),
        args: vec![],
        sandbox_override: Some(sandbox),
        agent_id: "test".to_string(),
        deployment_receipt_id: None,
    };

    let result = engine.execute(request).await;
    match result {
        Ok(r) => {
            // Output should be truncated
            assert!(
                r.stdout.len() <= 200, // Some buffer for truncation
                "Output should be limited. Got {} bytes",
                r.stdout.len()
            );
        }
        Err(ExecutionError::OutputLimitExceeded(_, _)) => {
            // Also acceptable
        }
        Err(e) => {
            panic!("Unexpected error: {:?}", e);
        }
    }
}

// ============================================================================
// Runtime Detection
// ============================================================================

#[test]
fn test_runtime_from_str_loose() {
    assert_eq!(Runtime::from_str_loose("python"), Some(Runtime::Python));
    assert_eq!(Runtime::from_str_loose("python3"), Some(Runtime::Python));
    assert_eq!(Runtime::from_str_loose("node"), Some(Runtime::NodeJs));
    assert_eq!(Runtime::from_str_loose("nodejs"), Some(Runtime::NodeJs));
    assert_eq!(Runtime::from_str_loose("javascript"), Some(Runtime::NodeJs));
    assert_eq!(Runtime::from_str_loose("bash"), Some(Runtime::Shell));
    assert_eq!(Runtime::from_str_loose("shell"), Some(Runtime::Shell));
    assert_eq!(Runtime::from_str_loose("sh"), Some(Runtime::Shell));
    assert_eq!(Runtime::from_str_loose("terminal"), Some(Runtime::Shell));
    assert_eq!(Runtime::from_str_loose("zsh"), Some(Runtime::Shell));
    assert_eq!(Runtime::from_str_loose("lua"), None);
}

// ============================================================================
// Sandbox Config
// ============================================================================

#[test]
fn test_sandbox_capabilities() {
    let config = SandboxConfig::default();
    assert!(config.has_capability(&SandboxCapability::ReadSandbox));
    assert!(config.has_capability(&SandboxCapability::WriteSandbox));
    assert!(config.has_capability(&SandboxCapability::Stdout));
    assert!(!config.has_capability(&SandboxCapability::SpawnProcess));
    assert!(!config.has_capability(&SandboxCapability::ReadEnv));
}

#[test]
fn test_sandbox_untrusted_vs_internal() {
    let untrusted = SandboxConfig::untrusted();
    let internal = SandboxConfig::internal();

    assert_eq!(untrusted.use_os_isolation, cfg!(target_os = "linux"));
    assert!(!internal.use_os_isolation);
    assert!(internal.timeout_ms > untrusted.timeout_ms);
    assert!(internal.memory_limit_bytes > untrusted.memory_limit_bytes);
}

// ============================================================================
// Concurrent Execution
// ============================================================================

#[tokio::test]
#[ignore] // Requires Python runtime on host
async fn test_concurrent_executions() {
    let engine = std::sync::Arc::new(ExecutionEngine::new().await.expect("engine init"));

    let mut handles = vec![];
    for i in 0..5 {
        let eng = engine.clone();
        handles.push(tokio::spawn(async move {
            let request = ExecutionRequest {
                request_id: format!("concurrent-{}", i),
                runtime: Runtime::Python,
                code: format!("print('task-{}')", i),
                args: vec![],
                sandbox_override: None,
                agent_id: "test".to_string(),
                deployment_receipt_id: None,
            };
            eng.execute(request).await
        }));
    }

    let results: Vec<_> = futures::future::join_all(handles).await;
    for (i, result) in results.into_iter().enumerate() {
        let result = result.expect("join").expect("execute");
        assert!(result.success, "Task {} should succeed", i);
        assert!(
            result.stdout.contains(&format!("task-{}", i)),
            "Task {} output mismatch: '{}'",
            i,
            result.stdout
        );
    }
}
