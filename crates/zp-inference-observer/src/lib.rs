//! zp-inference-observer — typed reader for DFlash observation JSONL events.
//!
//! Consumes the JSONL stream produced by `scripts/dflash-observation-emitter.py`
//! (see `docs/design/OBSERVATION-PLANE-2026-07.md` §"Inference telemetry")
//! and exposes each event as a typed [`InferenceObservation`] value.
//!
//! # Scope
//!
//! This crate deliberately stops before signing and chain-append. It provides:
//!
//! - Serde types matching the Python emitter's JSONL output.
//! - A poll-based tailer that yields new events as they arrive.
//! - Enough structure for substrate-side integration (in `zp-server` or a
//!   new `zp-inference-observation-emitter` crate) to loop over the stream,
//!   build a `zp_receipt::Receipt` via `Receipt::observation(...)` with
//!   `ClaimMetadata::Observation { observation_type, ... }` and extensions
//!   under `zp.observation.inference.*`, sign with Genesis, and append.
//!
//! # Why standalone
//!
//! Ships as its own Cargo workspace (`[workspace]` in Cargo.toml) so it can
//! build and be tested independently of the substrate's ~40-crate workspace.
//! When ready to integrate, remove the `[workspace]` table and add the crate
//! to `crates/` in the root workspace.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Event schema — mirrors scripts/dflash-observation-emitter.py output.
// ---------------------------------------------------------------------------

/// Bounds of one rolling window over which an acceptance rate was computed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Window {
    /// Window open time in UTC (ISO-8601, "YYYY-MM-DDTHH:MM:SSZ").
    pub start_wall_utc: String,
    /// Window close time in UTC (same shape).
    pub end_wall_utc: String,
    /// Duration in seconds, computed from server-side uptime deltas.
    pub duration_s: f64,
}

/// `observation:inference:drafter_acceptance` — emitted per window closure.
///
/// Corresponds to MODEL-DOSSIER-2026-07 §"Continuous drift signal" and
/// OBSERVATION-PLANE-2026-07 §"Inference telemetry" (Surface 7). When
/// substrate-side receipt emission wraps this in a
/// `Receipt::observation(observer_id="dflash-emitter")`, the payload maps
/// to `ClaimMetadata::Observation { observation_type: "inference:drafter_acceptance", ... }`
/// plus `zp.observation.inference.*` extensions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DrafterAcceptanceEvent {
    pub target_model_id: String,
    pub drafter_id: String,
    pub window: Window,
    pub target_tokens_in_window: u64,
    pub drafted_tokens_in_window: u64,
    /// None when the window had zero drafted tokens.
    pub mean_acceptance_rate: Option<f64>,
    /// Not populated by the current emitter — requires per-token accept/reject
    /// stream that dflash-mlx's /metrics endpoint doesn't expose. Placeholder
    /// so the schema is stable across future emitter versions.
    pub position_wise_acceptance_curve: Option<serde_json::Value>,
    /// Not populated by the current emitter — requires per-request workload
    /// classification. Placeholder for the same reason.
    pub workload_class_breakdown: Option<serde_json::Value>,
}

/// `substrate:characterization:drift_suspected` — emitted when the windowed
/// acceptance rate drops below the dossier-declared drift threshold.
///
/// Fires alongside a `DrafterAcceptanceEvent` for the same window. Consumed
/// by CIRCUIT-BREAKER as a trigger class per that spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriftSuspectedEvent {
    /// One of "declarative" | "drafter" | "both". Emitter currently only
    /// produces drift for the drafter serialization.
    pub characterization_form: String,
    pub target_model_id: String,
    pub drafter_id: String,
    /// Free-form label naming the specific triggering signal — currently
    /// always `"drafter_acceptance_below_threshold"` from this emitter.
    pub trigger: String,
    pub observed_mean_acceptance_rate: Option<f64>,
    pub declared_threshold: f64,
    pub window: Window,
}

/// A single JSONL event from the observation stream. Discriminated by
/// `event_type`.
///
/// Untagged with a fallback so unknown event types don't fail the tail —
/// they surface as [`Unknown`](InferenceObservation::Unknown) and the caller
/// can log-and-continue. This matters because the emitter may grow new
/// event types (per-request telemetry, workload-class breakdown, etc.)
/// ahead of consumers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum InferenceObservation {
    #[serde(rename = "observation:inference:drafter_acceptance")]
    DrafterAcceptance(DrafterAcceptanceEvent),
    #[serde(rename = "substrate:characterization:drift_suspected")]
    DriftSuspected(DriftSuspectedEvent),
    /// Any event whose `event_type` this version of the crate doesn't
    /// recognize. Carries the raw JSON so log-and-continue is possible.
    #[serde(other)]
    Unknown,
}

impl InferenceObservation {
    /// A short kind label for logging.
    pub fn kind(&self) -> &'static str {
        match self {
            InferenceObservation::DrafterAcceptance(_) => "drafter_acceptance",
            InferenceObservation::DriftSuspected(_) => "drift_suspected",
            InferenceObservation::Unknown => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Tail reader — poll-based, stdlib only, follows one file.
// ---------------------------------------------------------------------------

/// Config for the tail reader.
#[derive(Debug, Clone)]
pub struct TailConfig {
    /// Absolute path to the JSONL file to tail.
    pub path: PathBuf,
    /// How long to sleep between EOF checks. 500ms is a reasonable default
    /// — the emitter writes at window-close cadence (default 60s), so poll
    /// overhead is dominated by whatever the substrate does with the events.
    pub poll_interval: Duration,
    /// If true, start reading from the beginning of file (replay all past
    /// events). If false, seek to end and only surface new events.
    pub from_beginning: bool,
    /// If true, stop when EOF is reached with no new bytes for one poll
    /// interval. Useful for one-shot replay / testing. In production, false.
    pub stop_at_eof: bool,
}

impl Default for TailConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::new(),
            poll_interval: Duration::from_millis(500),
            from_beginning: false,
            stop_at_eof: false,
        }
    }
}

/// A parsed event plus its source position, so callers can persist "last
/// processed byte offset" for resume-after-restart.
#[derive(Debug, Clone)]
pub struct TailedEvent {
    pub event: InferenceObservation,
    /// Byte offset in the file just after this event's newline.
    pub end_offset: u64,
    /// Raw JSON of the line, before parsing — useful for logging and for
    /// building the receipt's `content_hash` off the exact bytes that
    /// were observed.
    pub raw_line: String,
}

/// Tail a JSONL file and invoke `on_event` for each parsed event.
///
/// Returns after receiving `stop_at_eof` OR when a fatal I/O error occurs.
/// For long-running substrate-side integration, hold this call open on a
/// dedicated thread or async task.
pub fn tail<F>(config: TailConfig, mut on_event: F) -> Result<()>
where
    F: FnMut(TailedEvent),
{
    let mut file = File::open(&config.path)
        .with_context(|| format!("open {}", config.path.display()))?;
    if !config.from_beginning {
        file.seek(SeekFrom::End(0))
            .context("seek to end of file")?;
    }
    let mut reader = BufReader::new(file);
    let mut buf = String::new();
    loop {
        buf.clear();
        let bytes_read = reader
            .read_line(&mut buf)
            .with_context(|| format!("read from {}", config.path.display()))?;
        if bytes_read == 0 {
            // EOF — either bail or sleep and try again.
            if config.stop_at_eof {
                return Ok(());
            }
            std::thread::sleep(config.poll_interval);
            continue;
        }
        // Only surface complete lines (with trailing newline). Partial lines
        // — no newline yet — are put back by leaving the position advanced;
        // BufReader::read_line already includes the partial content in buf.
        // Skip if not terminated (writer still working on this line).
        if !buf.ends_with('\n') {
            // Rewind so we re-read this partial line on the next iteration.
            let back = -(bytes_read as i64);
            reader.seek_relative(back)?;
            std::thread::sleep(config.poll_interval);
            continue;
        }
        let raw_line = buf.trim_end_matches('\n').to_string();
        if raw_line.is_empty() {
            continue;
        }
        let end_offset = reader.stream_position()?;
        match serde_json::from_str::<InferenceObservation>(&raw_line) {
            Ok(event) => {
                on_event(TailedEvent {
                    event,
                    end_offset,
                    raw_line,
                });
            }
            Err(e) => {
                // Malformed line — log and continue. In production this
                // should probably surface as a substrate-observability
                // finding rather than a silent skip.
                eprintln!(
                    "warning: malformed JSONL at offset {}: {} (raw: {})",
                    end_offset,
                    e,
                    &raw_line.chars().take(160).collect::<String>()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_drafter_acceptance() {
        let src = serde_json::json!({
            "event_type": "observation:inference:drafter_acceptance",
            "target_model_id": "Qwen/Qwen3-8B",
            "drafter_id": "z-lab/Qwen3-8B-DFlash-b16",
            "window": {
                "start_wall_utc": "2026-07-27T14:00:00Z",
                "end_wall_utc":   "2026-07-27T14:01:03Z",
                "duration_s":     63.0
            },
            "target_tokens_in_window": 742,
            "drafted_tokens_in_window": 1104,
            "mean_acceptance_rate":    0.7482,
            "position_wise_acceptance_curve": null,
            "workload_class_breakdown": null
        });
        let parsed: InferenceObservation = serde_json::from_value(src).unwrap();
        match parsed {
            InferenceObservation::DrafterAcceptance(e) => {
                assert_eq!(e.target_model_id, "Qwen/Qwen3-8B");
                assert_eq!(e.drafted_tokens_in_window, 1104);
                assert!((e.mean_acceptance_rate.unwrap() - 0.7482).abs() < 1e-6);
                assert_eq!(e.window.duration_s, 63.0);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_drift_suspected() {
        let src = serde_json::json!({
            "event_type": "substrate:characterization:drift_suspected",
            "characterization_form": "drafter",
            "target_model_id": "Qwen/Qwen3-8B",
            "drafter_id": "z-lab/Qwen3-8B-DFlash-b16",
            "trigger": "drafter_acceptance_below_threshold",
            "observed_mean_acceptance_rate": 0.482,
            "declared_threshold": 0.55,
            "window": {
                "start_wall_utc": "2026-07-27T14:00:00Z",
                "end_wall_utc":   "2026-07-27T14:01:03Z",
                "duration_s":     63.0
            }
        });
        let parsed: InferenceObservation = serde_json::from_value(src).unwrap();
        match parsed {
            InferenceObservation::DriftSuspected(e) => {
                assert_eq!(e.characterization_form, "drafter");
                assert_eq!(e.trigger, "drafter_acceptance_below_threshold");
                assert!((e.declared_threshold - 0.55).abs() < 1e-6);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn unknown_event_type_becomes_unknown() {
        let src = serde_json::json!({
            "event_type": "observation:inference:something_future",
            "target_model_id": "x",
        });
        let parsed: InferenceObservation = serde_json::from_value(src).unwrap();
        assert!(matches!(parsed, InferenceObservation::Unknown));
    }
}
