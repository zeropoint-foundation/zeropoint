//! zp-inference-observer — CLI demo of the tail reader.
//!
//! Prints each parsed event to stdout, one JSON object per line, in the
//! shape the eventual substrate-side receipt emission will consume. Useful
//! for validating the JSONL stream before wiring the signed-receipt path.
//!
//! Usage:
//!
//! ```text
//! zp-inference-observer \
//!   --path ~/projects/zeropoint/.observations/inference/drafter_acceptance-20260727.jsonl
//!
//! # Replay from beginning, exit at EOF:
//! zp-inference-observer --path FILE --from-beginning --stop-at-eof
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use zp_inference_observer::{tail, InferenceObservation, TailConfig};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Tail DFlash observation JSONL and print each event to stdout."
)]
struct Cli {
    /// Path to the JSONL file to tail.
    #[arg(long)]
    path: PathBuf,

    /// Poll interval in milliseconds between EOF checks.
    #[arg(long, default_value_t = 500)]
    poll_ms: u64,

    /// Start reading from the beginning of the file (replay past events).
    #[arg(long)]
    from_beginning: bool,

    /// Exit when EOF is reached (useful for one-shot replay / testing).
    #[arg(long)]
    stop_at_eof: bool,

    /// Print raw JSON lines instead of a summarized digest.
    #[arg(long)]
    raw: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = TailConfig {
        path: cli.path.clone(),
        poll_interval: Duration::from_millis(cli.poll_ms),
        from_beginning: cli.from_beginning,
        stop_at_eof: cli.stop_at_eof,
    };

    eprintln!(
        "zp-inference-observer: tailing {} (from_beginning={}, stop_at_eof={})",
        cli.path.display(),
        cli.from_beginning,
        cli.stop_at_eof,
    );

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut event_count: u64 = 0;
    let mut drift_count: u64 = 0;
    let mut unknown_count: u64 = 0;

    tail(config, |tailed| {
        event_count += 1;
        match &tailed.event {
            InferenceObservation::DriftSuspected(_) => drift_count += 1,
            InferenceObservation::Unknown => unknown_count += 1,
            _ => {}
        }
        if cli.raw {
            writeln!(out, "{}", tailed.raw_line).ok();
        } else {
            let digest = digest(&tailed.event);
            writeln!(
                out,
                "[{:>6}] offset={} {} {}",
                event_count,
                tailed.end_offset,
                tailed.event.kind(),
                digest,
            )
            .ok();
        }
    })
    .context("tail loop")?;

    eprintln!(
        "\nexit: {} events ({} drift, {} unknown)",
        event_count, drift_count, unknown_count
    );
    Ok(())
}

fn digest(event: &InferenceObservation) -> String {
    match event {
        InferenceObservation::DrafterAcceptance(e) => {
            let rate = e
                .mean_acceptance_rate
                .map(|r| format!("{:.2}%", r * 100.0))
                .unwrap_or_else(|| "(none)".to_string());
            format!(
                "target={} drafter={} drafted={} rate={} window={}s",
                e.target_model_id,
                short_id(&e.drafter_id),
                e.drafted_tokens_in_window,
                rate,
                e.window.duration_s,
            )
        }
        InferenceObservation::DriftSuspected(e) => {
            let rate = e
                .observed_mean_acceptance_rate
                .map(|r| format!("{:.2}%", r * 100.0))
                .unwrap_or_else(|| "(none)".to_string());
            format!(
                "target={} drafter={} rate={} < threshold={:.2}% trigger={}",
                e.target_model_id,
                short_id(&e.drafter_id),
                rate,
                e.declared_threshold * 100.0,
                e.trigger,
            )
        }
        InferenceObservation::Unknown => "(unrecognized event_type)".to_string(),
    }
}

fn short_id(id: &str) -> String {
    id.rsplit_once('/')
        .map(|(_, tail)| tail.to_string())
        .unwrap_or_else(|| id.to_string())
}
