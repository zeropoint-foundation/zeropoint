//! Inference posture selection, setup guidance, model pull, and system resource detection.

use super::{OnboardAction, OnboardEvent, OnboardState};
use serde::Serialize;
use zp_core::paths as zp_paths;

/// Set the user's inference posture choice.
pub async fn handle_set_inference_posture(
    action: &OnboardAction,
    state: &mut OnboardState,
) -> Vec<OnboardEvent> {
    let posture = action
        .params
        .get("posture")
        .and_then(|v| v.as_str())
        .unwrap_or("mixed")
        .to_string();

    state.inference_posture = Some(posture.clone());
    state.step = 4;

    vec![OnboardEvent::new(
        "inference_posture_set",
        serde_json::json!({
            "posture": posture,
        }),
    )]
}

/// Return platform-specific install instructions and model recommendations.
///
/// This is the stewardship flow: rather than pointing users to a download page
/// and abandoning them, ZeroPoint walks them through the entire setup.
pub async fn handle_setup_guidance(action: &OnboardAction) -> Vec<OnboardEvent> {
    let runtime_pref = action
        .params
        .get("runtime")
        .and_then(|v| v.as_str())
        .unwrap_or("ollama");

    let system = detect_system_resources();

    let platform = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };

    // ── Install instructions per runtime × platform ──────────
    let install = match (runtime_pref, platform) {
        ("ollama", "macos") => SetupInstall {
            runtime: "Ollama".into(),
            method: "Homebrew or direct download".into(),
            commands: vec!["brew install ollama".into(), "ollama serve".into()],
            alt_url: Some("https://ollama.com/download/mac".into()),
            verify_command: "ollama --version".into(),
            notes: "Ollama runs as a background service after install. If using Homebrew, \
                    it starts automatically."
                .into(),
        },
        ("ollama", "linux") => SetupInstall {
            runtime: "Ollama".into(),
            method: "Official install script".into(),
            commands: vec![
                "curl -fsSL https://ollama.com/install.sh | sh".into(),
                "ollama serve".into(),
            ],
            alt_url: Some("https://ollama.com/download/linux".into()),
            verify_command: "ollama --version".into(),
            notes: "The install script sets up a systemd service. Ollama will start on boot."
                .into(),
        },
        ("ollama", "windows") => SetupInstall {
            runtime: "Ollama".into(),
            method: "Windows installer".into(),
            commands: vec!["winget install Ollama.Ollama".into()],
            alt_url: Some("https://ollama.com/download/windows".into()),
            verify_command: "ollama --version".into(),
            notes: "After install, Ollama runs in the system tray. You can also use \
                    the direct installer from the download page."
                .into(),
        },
        ("lm-studio", _) => SetupInstall {
            runtime: "LM Studio".into(),
            method: "Desktop application".into(),
            commands: vec![],
            alt_url: Some("https://lmstudio.ai".into()),
            verify_command: String::new(),
            notes: "Download and install LM Studio. Models are downloaded through the app's \
                    built-in model browser. Start the local server from the Developer tab."
                .into(),
        },
        ("jan", _) => SetupInstall {
            runtime: "Jan".into(),
            method: "Desktop application".into(),
            commands: vec![],
            alt_url: Some("https://jan.ai".into()),
            verify_command: String::new(),
            notes: "Download and install Jan. It provides a one-click model setup — choose a \
                    model from the hub and Jan handles the rest. Enable the API server in \
                    Settings → Advanced."
                .into(),
        },
        _ => SetupInstall {
            runtime: runtime_pref.to_string(),
            method: "Manual install".into(),
            commands: vec![],
            alt_url: None,
            verify_command: String::new(),
            notes: "Install your preferred runtime and ensure it serves an OpenAI-compatible \
                    API on localhost."
                .into(),
        },
    };

    // ── Model recommendation based on hardware ───────────────
    let model_rec = recommend_model(&system, runtime_pref);

    vec![OnboardEvent::new(
        "setup_guidance",
        serde_json::json!({
            "platform": platform,
            "runtime": runtime_pref,
            "install": install,
            "model": model_rec,
            "system": system,
        }),
    )]
}

/// Start a model pull in the background.
pub async fn handle_start_model_pull(action: &OnboardAction) -> Vec<OnboardEvent> {
    let model_id = match action.params.get("model_id").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => {
            return vec![OnboardEvent::error(
                "start_model_pull requires 'model_id' parameter",
            )];
        }
    };

    let runtime = action
        .params
        .get("runtime")
        .and_then(|v| v.as_str())
        .unwrap_or("ollama");

    match runtime {
        "ollama" => {
            // Spawn ollama pull as a detached background process
            match std::process::Command::new("ollama")
                .args(["pull", model_id])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                Ok(_child) => {
                    tracing::info!("Background model pull started: ollama pull {}", model_id);
                    vec![OnboardEvent::new(
                        "model_pull_started",
                        serde_json::json!({
                            "model_id": model_id,
                            "runtime": runtime,
                            "message": format!(
                                "Downloading {} in the background. Continue with onboarding — \
                                 the model will be available when the download completes.",
                                model_id
                            ),
                        }),
                    )]
                }
                Err(e) => {
                    tracing::warn!("Failed to start model pull: {}", e);
                    vec![OnboardEvent::new(
                        "model_pull_started",
                        serde_json::json!({
                            "model_id": model_id,
                            "runtime": runtime,
                            "error": true,
                            "message": format!(
                                "Could not start the download automatically. Run this in your terminal: \
                                 ollama pull {}",
                                model_id
                            ),
                        }),
                    )]
                }
            }
        }
        _ => {
            // GUI runtimes handle downloads through their own interface
            vec![OnboardEvent::new(
                "model_pull_started",
                serde_json::json!({
                    "model_id": model_id,
                    "runtime": runtime,
                    "message": format!(
                        "Search for '{}' in {}'s model browser and start the download. \
                         Continue with onboarding — the model will be available when ready.",
                        model_id, runtime
                    ),
                }),
            )]
        }
    }
}

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize)]
struct SetupInstall {
    runtime: String,
    method: String,
    commands: Vec<String>,
    alt_url: Option<String>,
    verify_command: String,
    notes: String,
}

#[derive(Debug, Clone, Serialize)]
struct ModelRecommendation {
    model_id: String,
    display_name: String,
    size: String,
    rationale: String,
    pull_command: String,
    source_url: Option<String>,
    last_verified: Option<String>,
    alternative: Option<ModelAlt>,
}

#[derive(Debug, Clone, Serialize)]
struct ModelAlt {
    model_id: String,
    display_name: String,
    size: String,
    pull_command: String,
    rationale: String,
    source_url: Option<String>,
}

/// Detect system RAM, CPU cores, chip, and GPU info for inference recommendations.
#[derive(Debug, Clone, Serialize)]
pub struct SystemResources {
    pub ram_gb: u64,
    pub cpu_cores: usize,
    pub chip: Option<String>,
    pub gpu: Option<String>,
    pub inference_memory_gb: u64,
    pub unified_memory: bool,
    pub local_inference_fit: String,
    pub recommendation: String,
}

// ============================================================================
// System resource detection (pub for use by detect.rs)
// ============================================================================

pub fn detect_system_resources() -> SystemResources {
    let cpu_cores = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);

    let (ram_gb, chip) = detect_platform_resources();
    let (gpu, gpu_vram_gb, unified_memory) = detect_gpu();

    let inference_memory_gb = if unified_memory {
        ram_gb
    } else if gpu_vram_gb > 0 {
        gpu_vram_gb
    } else {
        ram_gb
    };

    let has_gpu = gpu.is_some();
    let (fit, recommendation) = if ram_gb == 0 && !has_gpu {
        (
            "unknown".to_string(),
            "System resources could not be detected. Mixed mode is a safe default.".to_string(),
        )
    } else if inference_memory_gb >= 16 {
        let gpu_note = if unified_memory {
            format!("{}GB unified memory", ram_gb)
        } else if let Some(ref g) = gpu {
            g.to_string()
        } else {
            format!("{}GB RAM", ram_gb)
        };
        (
            "strong".to_string(),
            format!(
                "{} — local models (up to 30B+) will run well here. Mixed mode recommended.",
                gpu_note
            ),
        )
    } else if inference_memory_gb >= 8 {
        let gpu_note = if unified_memory {
            format!("{}GB unified memory", ram_gb)
        } else if let Some(ref g) = gpu {
            g.to_string()
        } else {
            format!("{}GB RAM", ram_gb)
        };
        (
            "moderate".to_string(),
            format!(
                "{} — smaller local models (7B–8B) will work. Mixed mode gives you flexibility.",
                gpu_note
            ),
        )
    } else if has_gpu {
        (
            "moderate".to_string(),
            format!(
                "{} — can handle small models. Mixed mode lets you offload larger tasks to the cloud.",
                gpu.as_deref().unwrap_or("GPU detected")
            ),
        )
    } else {
        (
            "limited".to_string(),
            format!(
                "{}GB RAM, no GPU detected — cloud inference is the practical choice for now.",
                ram_gb
            ),
        )
    };

    SystemResources {
        ram_gb,
        cpu_cores,
        chip,
        gpu,
        inference_memory_gb,
        unified_memory,
        local_inference_fit: fit,
        recommendation,
    }
}

// ============================================================================
// Model recommendations
// ============================================================================

fn recommend_model(system: &SystemResources, runtime: &str) -> ModelRecommendation {
    if let Some(rec) = load_model_override(system.inference_memory_gb, runtime) {
        return rec;
    }

    let mem = system.inference_memory_gb;
    let pull_cmd = |model: &str| -> String {
        match runtime {
            "ollama" => format!("ollama pull {}", model),
            "lm-studio" => format!("Search for '{}' in LM Studio's model browser", model),
            "jan" => format!("Search for '{}' in Jan's model hub", model),
            _ => format!("Download {}", model),
        }
    };

    let verified = Some("2026-03-22".to_string());

    if mem >= 32 {
        ModelRecommendation {
            model_id: "qwen3:8b".into(),
            display_name: "Qwen 3 8B".into(),
            size: "~5.2 GB".into(),
            rationale: format!(
                "Leads benchmarks on math, coding, and reasoning at this size class. \
                 Supports thinking mode for complex tasks. With {}GB available, you \
                 have headroom for larger models too.",
                mem
            ),
            pull_command: pull_cmd("qwen3:8b"),
            source_url: Some("https://huggingface.co/Qwen/Qwen3-8B".into()),
            last_verified: verified.clone(),
            alternative: Some(ModelAlt {
                model_id: "gemma3:12b".into(),
                display_name: "Gemma 3 12B".into(),
                size: "~8.1 GB".into(),
                pull_command: pull_cmd("gemma3:12b"),
                rationale: "Multimodal (text + vision), 128K context window, strong \
                           general-purpose. Good if you need image understanding."
                    .into(),
                source_url: Some("https://ai.google.dev/gemma/docs".into()),
            }),
        }
    } else if mem >= 16 {
        ModelRecommendation {
            model_id: "qwen3:8b".into(),
            display_name: "Qwen 3 8B".into(),
            size: "~5.2 GB".into(),
            rationale: format!(
                "Best balance of speed and capability for {}GB. Handles \
                 summarization, code completion, and general tasks at state-of-the-art \
                 quality for its size.",
                mem
            ),
            pull_command: pull_cmd("qwen3:8b"),
            source_url: Some("https://huggingface.co/Qwen/Qwen3-8B".into()),
            last_verified: verified.clone(),
            alternative: Some(ModelAlt {
                model_id: "llama3.3:8b".into(),
                display_name: "Llama 3.3 8B".into(),
                size: "~4.9 GB".into(),
                pull_command: pull_cmd("llama3.3:8b"),
                rationale: "Solid all-rounder with the largest ecosystem. \
                           Great tool-use and instruction-following."
                    .into(),
                source_url: Some("https://huggingface.co/meta-llama/Llama-3.3-8B-Instruct".into()),
            }),
        }
    } else if mem >= 8 {
        ModelRecommendation {
            model_id: "gemma3:4b".into(),
            display_name: "Gemma 3 4B".into(),
            size: "~3.0 GB".into(),
            rationale: format!(
                "Outperforms last-generation 27B models at a fraction of the size. \
                 Multimodal (text + images), 128K context, very fast (~60-80 tok/s). \
                 Fits comfortably in {}GB at Q8 quality.",
                mem
            ),
            pull_command: pull_cmd("gemma3:4b"),
            source_url: Some("https://ai.google.dev/gemma/docs".into()),
            last_verified: verified.clone(),
            alternative: Some(ModelAlt {
                model_id: "phi4-mini".into(),
                display_name: "Phi-4 Mini (3.8B)".into(),
                size: "~2.5 GB".into(),
                pull_command: pull_cmd("phi4-mini"),
                rationale: "Excels at math and coding (80.4% on MATH benchmark — \
                           beats models twice its size). Best pick if your work is \
                           code-heavy."
                    .into(),
                source_url: Some("https://huggingface.co/microsoft/Phi-4-mini-instruct".into()),
            }),
        }
    } else {
        ModelRecommendation {
            model_id: "qwen3:0.6b".into(),
            display_name: "Qwen 3 0.6B".into(),
            size: "~523 MB".into(),
            rationale: "Smallest model with thinking mode — handles basic summarization, \
                       Q&A, and simple code tasks. At 523MB, it runs fast even on constrained \
                       hardware. Consider Mixed mode to offload complex work to the cloud."
                .into(),
            pull_command: pull_cmd("qwen3:0.6b"),
            source_url: Some("https://huggingface.co/Qwen/Qwen3-0.6B".into()),
            last_verified: verified,
            alternative: Some(ModelAlt {
                model_id: "gemma3:1b".into(),
                display_name: "Gemma 3 1B".into(),
                size: "~815 MB".into(),
                pull_command: pull_cmd("gemma3:1b"),
                rationale: "Multimodal at 1B parameters — can process both text and images. \
                           128K context window."
                    .into(),
                source_url: Some("https://ai.google.dev/gemma/docs".into()),
            }),
        }
    }
}

fn load_model_override(inference_memory_gb: u64, runtime: &str) -> Option<ModelRecommendation> {
    let path = zp_paths::home()
        .ok()?
        .join("config")
        .join("model-recommendations.toml");

    let content = std::fs::read_to_string(&path).ok()?;
    let table: toml::Value = content.parse().ok()?;

    let tiers = table.get("tiers")?.as_array()?;

    let mut best_tier: Option<&toml::Value> = None;
    let mut best_min: u64 = 0;

    for tier in tiers {
        let min = tier
            .get("min_memory_gb")
            .and_then(|v| v.as_integer())
            .unwrap_or(0) as u64;
        if inference_memory_gb >= min && min >= best_min {
            best_tier = Some(tier);
            best_min = min;
        }
    }

    let tier = best_tier?;

    let pull_cmd = |model: &str| -> String {
        match runtime {
            "ollama" => format!("ollama pull {}", model),
            "lm-studio" => format!("Search for '{}' in LM Studio's model browser", model),
            "jan" => format!("Search for '{}' in Jan's model hub", model),
            _ => format!("Download {}", model),
        }
    };

    let model_id = tier.get("model_id")?.as_str()?;
    let display_name = tier.get("display_name")?.as_str().unwrap_or(model_id);
    let size = tier.get("size")?.as_str().unwrap_or("unknown");
    let rationale = tier.get("rationale")?.as_str().unwrap_or("");

    let source_url = tier
        .get("source_url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let last_verified = tier
        .get("last_verified")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let alternative = tier.get("alternative").and_then(|alt| {
        let alt_id = alt.get("model_id")?.as_str()?;
        Some(ModelAlt {
            model_id: alt_id.to_string(),
            display_name: alt
                .get("display_name")
                .and_then(|v| v.as_str())
                .unwrap_or(alt_id)
                .to_string(),
            size: alt
                .get("size")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            pull_command: pull_cmd(alt_id),
            rationale: alt
                .get("rationale")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            source_url: alt
                .get("source_url")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        })
    });

    Some(ModelRecommendation {
        model_id: model_id.to_string(),
        display_name: display_name.to_string(),
        size: size.to_string(),
        rationale: rationale.to_string(),
        pull_command: pull_cmd(model_id),
        source_url,
        last_verified,
        alternative,
    })
}

// ============================================================================
// Platform resource detection
// ============================================================================

/// Detect GPU/accelerator and VRAM. Returns (description, vram_gb, is_unified).
fn detect_gpu() -> (Option<String>, u64, bool) {
    #[cfg(target_os = "macos")]
    {
        let chip = std::process::Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        if chip.contains("Apple") {
            let ram_gb = std::process::Command::new("sysctl")
                .args(["-n", "hw.memsize"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(|bytes| bytes / (1024 * 1024 * 1024))
                .unwrap_or(0);

            let desc = format!("{} (unified {}GB)", chip, ram_gb);
            return (Some(desc), ram_gb, true);
        }

        let gpu_info = std::process::Command::new("system_profiler")
            .args(["SPDisplaysDataType", "-json"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());

        if let Some(info) = gpu_info {
            if let Some(displays) = info.get("SPDisplaysDataType").and_then(|d| d.as_array()) {
                for display in displays {
                    let name = display
                        .get("sppci_model")
                        .and_then(|n| n.as_str())
                        .unwrap_or("Unknown GPU");
                    let vram = display
                        .get("spdisplays_vram_shared")
                        .or_else(|| display.get("spdisplays_vram"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let vram_gb = parse_vram_string(vram);
                    if vram_gb > 0 {
                        return (
                            Some(format!("{} ({}GB VRAM)", name, vram_gb)),
                            vram_gb,
                            false,
                        );
                    }
                }
            }
        }

        (None, 0, false)
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("nvidia-smi")
            .args([
                "--query-gpu=name,memory.total",
                "--format=csv,noheader,nounits",
            ])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if let Some(line) = stdout.lines().next() {
                    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                    if parts.len() >= 2 {
                        let name = parts[0];
                        let vram_mb: u64 = parts[1].parse().unwrap_or(0);
                        let vram_gb = vram_mb / 1024;
                        return (
                            Some(format!("{} ({}GB VRAM)", name, vram_gb)),
                            vram_gb,
                            false,
                        );
                    }
                }
            }
        }

        if let Ok(output) = std::process::Command::new("rocm-smi")
            .args(["--showmeminfo", "vram", "--csv"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().skip(1) {
                    if let Some(total_str) = line.split(',').nth(1) {
                        if let Ok(vram_bytes) = total_str.trim().parse::<u64>() {
                            let vram_gb = vram_bytes / (1024 * 1024 * 1024);
                            return (
                                Some(format!("AMD GPU ({}GB VRAM)", vram_gb)),
                                vram_gb,
                                false,
                            );
                        }
                    }
                }
            }
        }

        (None, 0, false)
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("nvidia-smi")
            .args([
                "--query-gpu=name,memory.total",
                "--format=csv,noheader,nounits",
            ])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if let Some(line) = stdout.lines().next() {
                    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                    if parts.len() >= 2 {
                        let name = parts[0];
                        let vram_mb: u64 = parts[1].parse().unwrap_or(0);
                        let vram_gb = vram_mb / 1024;
                        return (
                            Some(format!("{} ({}GB VRAM)", name, vram_gb)),
                            vram_gb,
                            false,
                        );
                    }
                }
            }
        }

        if let Ok(output) = std::process::Command::new("wmic")
            .args([
                "path",
                "win32_VideoController",
                "get",
                "Name,AdapterRAM",
                "/value",
            ])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut name = String::new();
                let mut vram_bytes: u64 = 0;
                for line in stdout.lines() {
                    let line = line.trim();
                    if let Some(n) = line.strip_prefix("Name=") {
                        name = n.to_string();
                    }
                    if let Some(v) = line.strip_prefix("AdapterRAM=") {
                        vram_bytes = v.parse().unwrap_or(0);
                    }
                }
                if !name.is_empty() && vram_bytes > 0 {
                    let vram_gb = vram_bytes / (1024 * 1024 * 1024);
                    return (
                        Some(format!("{} ({}GB VRAM)", name, vram_gb)),
                        vram_gb,
                        false,
                    );
                }
            }
        }

        (None, 0, false)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        (None, 0, false)
    }
}

/// Parse VRAM strings like "8 GB", "8192 MB", "8GB".
#[allow(dead_code)]
fn parse_vram_string(s: &str) -> u64 {
    let s = s.trim().to_uppercase();
    if let Some(gb_str) = s.strip_suffix("GB").or_else(|| s.strip_suffix(" GB")) {
        gb_str.trim().parse().unwrap_or(0)
    } else if let Some(mb_str) = s.strip_suffix("MB").or_else(|| s.strip_suffix(" MB")) {
        mb_str.trim().parse::<u64>().unwrap_or(0) / 1024
    } else {
        0
    }
}

/// Platform-specific RAM and chip detection.
fn detect_platform_resources() -> (u64, Option<String>) {
    #[cfg(target_os = "macos")]
    {
        let ram_gb = std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|bytes| bytes / (1024 * 1024 * 1024))
            .unwrap_or(0);

        let chip = std::process::Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        (ram_gb, chip)
    }

    #[cfg(target_os = "linux")]
    {
        let ram_gb = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|l| l.starts_with("MemTotal:"))
                    .and_then(|l| {
                        l.split_whitespace()
                            .nth(1)
                            .and_then(|kb| kb.parse::<u64>().ok())
                    })
            })
            .map(|kb| kb / (1024 * 1024))
            .unwrap_or(0);

        let chip = std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|l| l.starts_with("model name"))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|s| s.trim().to_string())
            });

        (ram_gb, chip)
    }

    #[cfg(target_os = "windows")]
    {
        let ram_gb = std::process::Command::new("wmic")
            .args(["computersystem", "get", "TotalPhysicalMemory", "/value"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("TotalPhysicalMemory="))
                    .and_then(|l| l.split('=').nth(1))
                    .and_then(|v| v.trim().parse::<u64>().ok())
            })
            .map(|bytes| bytes / (1024 * 1024 * 1024))
            .unwrap_or(0);

        let chip = std::process::Command::new("wmic")
            .args(["cpu", "get", "Name", "/value"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Name="))
                    .and_then(|l| l.split('=').nth(1))
                    .map(|v| v.trim().to_string())
            })
            .filter(|s| !s.is_empty());

        (ram_gb, chip)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        (0, None)
    }
}
