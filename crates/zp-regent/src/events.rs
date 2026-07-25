//! Cognitive events — real-time telemetry from the Regent's pipeline.
//!
//! Each phase of the cognitive cycle emits a `CognitiveEvent` with
//! timing data. Consumers (SSE stream, CLI `--verbose`) can subscribe
//! to the event channel to get a consolidated feed of everything
//! the Regent does and where time is spent.

use serde::{Deserialize, Serialize};

/// A single event from the Regent's cognitive pipeline.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CognitiveEvent {
    /// Which phase of the pipeline produced this event.
    pub phase: Phase,
    /// Milliseconds elapsed for this phase (0 for start events).
    pub elapsed_ms: u64,
    /// Short detail string (model name, tool name, intent type, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// ISO 8601 timestamp.
    pub timestamp: String,
}

/// Phases of the Regent's cognitive cycle.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Operator input received, cycle starting.
    CycleStart,
    /// Perceive: chain + findings read, context assembled.
    Perceive,
    /// Inference request sent to model.
    InferenceStart,
    /// Inference response received from model.
    InferenceEnd,
    /// Intent parsed from model output.
    IntentParsed,
    /// Tool dispatched for execution.
    ToolDispatch,
    /// Tool execution completed.
    ToolComplete,
    /// Response delivered to operator.
    ResponseDelivered,
    /// Full cycle finished.
    CycleEnd,
    /// Work arc started (multi-cycle task).
    ArcStart,
    /// Work arc progress update — the glanceable one-liner.
    ArcProgress,
    /// Work arc completed or terminated.
    ArcEnd,
    /// Error during cycle.
    Error,
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Phase::CycleStart => write!(f, "cycle_start"),
            Phase::Perceive => write!(f, "perceive"),
            Phase::InferenceStart => write!(f, "inference_start"),
            Phase::InferenceEnd => write!(f, "inference_end"),
            Phase::IntentParsed => write!(f, "intent_parsed"),
            Phase::ToolDispatch => write!(f, "tool_dispatch"),
            Phase::ToolComplete => write!(f, "tool_complete"),
            Phase::ResponseDelivered => write!(f, "response_delivered"),
            Phase::CycleEnd => write!(f, "cycle_end"),
            Phase::ArcStart => write!(f, "arc_start"),
            Phase::ArcProgress => write!(f, "arc_progress"),
            Phase::ArcEnd => write!(f, "arc_end"),
            Phase::Error => write!(f, "error"),
        }
    }
}

impl CognitiveEvent {
    /// Create an event with timing.
    pub fn new(phase: Phase, elapsed_ms: u64) -> Self {
        Self {
            phase,
            elapsed_ms,
            detail: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Add detail to an event.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Type alias for the event sender half.
pub type EventTx = tokio::sync::broadcast::Sender<CognitiveEvent>;

/// Create a new cognitive event broadcast channel.
pub fn event_channel() -> (EventTx, tokio::sync::broadcast::Receiver<CognitiveEvent>) {
    tokio::sync::broadcast::channel(128)
}
