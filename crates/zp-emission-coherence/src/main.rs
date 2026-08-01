//! zp-emission-coherence — CLI demo: read one response from JSON on stdin,
//! run the heuristics, print the outcome as JSON on stdout.
//!
//! Useful for smoke-testing the crate before wiring it into Regent's
//! loop_runner. Also produces the exact `Outcome` JSON shape the substrate
//! integration will consume.
//!
//! Input schema (JSON on stdin):
//! ```json
//! {
//!   "cycle_id": "...",
//!   "model": "qwen3:8b",
//!   "text": "the model's response text",
//!   "token_ids": [1, 2, 3, ...],
//!   "log_probs": [-0.5, -1.2, ...],   // optional
//!   "sampling_params": { "temperature": 0.7, "top_p": 0.9 }
//! }
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::io::Read;

use zp_emission_coherence::{
    AnalyzerConfig, EmissionAnalyzer, EntropyBaseline, Response, SamplingParams,
};

#[derive(Deserialize)]
struct StdinResponse {
    cycle_id: String,
    model: String,
    text: String,
    token_ids: Vec<u32>,
    #[serde(default)]
    log_probs: Option<Vec<f64>>,
    #[serde(default)]
    sampling_params: SamplingParams,
}

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Run emission-coherence heuristics against one Regent response (JSON on stdin)."
)]
struct Cli {
    /// Provide an entropy baseline for the model (enables H3).
    /// Format: "model,mean,std_dev" (comma-separated so model IDs with
    /// colons like `qwen3:8b` work). May be given multiple times.
    #[arg(long, action = clap::ArgAction::Append)]
    baseline: Vec<String>,

    /// Length-window CV threshold (default 0.15).
    #[arg(long, default_value_t = 0.15)]
    cv_threshold: f64,

    /// Length window size (default 20). Fewer means H2 fires sooner but
    /// less reliably; the CLI runs a single response so H2 rarely fires
    /// here.
    #[arg(long, default_value_t = 20)]
    window_size: usize,

    /// If true, escalate any R1 case to R2 (adversarial-testing mode).
    #[arg(long)]
    escalate_r1_to_r2: bool,
}

fn parse_baseline(spec: &str) -> Result<(String, EntropyBaseline)> {
    let parts: Vec<&str> = spec.split(',').collect();
    if parts.len() != 3 {
        anyhow::bail!(
            "--baseline expects 'model,mean,std_dev' (comma-separated), got {:?}",
            spec
        );
    }
    let mean: f64 = parts[1].trim().parse().context("baseline mean")?;
    let std_dev: f64 = parts[2].trim().parse().context("baseline std_dev")?;
    Ok((
        parts[0].trim().to_string(),
        EntropyBaseline { mean, std_dev },
    ))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut config = AnalyzerConfig {
        length_window_size: cli.window_size,
        length_cv_threshold: cli.cv_threshold,
        entropy_baselines: Default::default(),
        escalate_r1_to_r2: cli.escalate_r1_to_r2,
    };
    for spec in &cli.baseline {
        let (model, baseline) = parse_baseline(spec)?;
        config.entropy_baselines.insert(model, baseline);
    }

    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    let input: StdinResponse = serde_json::from_str(&buf).context("parse stdin JSON")?;

    let mut analyzer = EmissionAnalyzer::new(config);
    let response = Response {
        cycle_id: &input.cycle_id,
        model: &input.model,
        token_ids: &input.token_ids,
        text: &input.text,
        log_probs: input.log_probs.as_deref(),
        sampling_params: input.sampling_params,
    };
    let outcome = analyzer.analyze(&response);

    let out = serde_json::to_string_pretty(&outcome)?;
    println!("{out}");
    Ok(())
}
