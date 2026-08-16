//! Chain narration artifact kind — the first backward-looking artifact.
//!
//! ## Composition rules
//!
//! The closer-drift bug class is eliminated by construction:
//! - `format_opener` and `format_closer` are deterministic Rust functions.
//! - The LLM is given ONLY the middle receipts and told explicitly not to open or close.
//! - The LLM cannot produce a closer because it is never shown the last receipt.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::artifact::{
    compute_artifact_id, Artifact, ArtifactContent, ArtifactId, ArtifactKind, LibraryError,
    LifecycleState, RenderConfig, SourceManifest,
};
use crate::library::Library;

/// Normalized receipt — the common shape across local and foundation sources.
/// Matches the `audit_normalize_entry` output in `zp-server`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedReceipt {
    pub id: String,
    pub claim: String,
    pub created_at: DateTime<Utc>,
}

/// The composition parts returned by `build_composition`.
/// The cockpit uses these to make the LLM call and submit back via `generate_candidate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainNarrationComposition {
    /// Deterministic opener sentence (Rust-generated, not LLM output).
    pub opener: String,
    /// The prompt to send to the LLM for the middle receipts.
    /// If `middle_receipts` is empty, this is an empty string.
    pub middle_prompt: String,
    /// Deterministic closer sentence (Rust-generated, not LLM output).
    pub closer: String,
    /// Source manifest (for the cockpit to include in the submit call).
    pub source_manifest: SourceManifest,
    /// Render config (for the cockpit to include in the submit call).
    pub render_config: RenderConfig,
    /// Whether there are any middle receipts to render.
    pub has_middle: bool,
}

/// Current composition rules version — bump when structural rules change.
pub const COMPOSITION_RULES_VERSION: u32 = 1;

/// Current render function version — bump when this module's logic changes.
pub const RENDER_FUNCTION_VERSION: u32 = 1;

/// Deterministic opener: first receipt → opening sentence.
///
/// No preamble, no "Here's a summary" service announcement.
/// Structural invariant: this is never delegated to the LLM.
pub fn format_opener(first: &NormalizedReceipt) -> String {
    format!(
        "{}: {}.",
        first.created_at.format("%B %-d"),
        first.claim.trim_end_matches('.')
    )
}

/// Deterministic closer: last receipt → closing sentence.
///
/// No wrap-up, no "let me know if..." sentence.
/// Structural invariant: the LLM is never asked to produce a closer.
/// Closer-drift is structurally impossible because the LLM never sees the last receipt.
pub fn format_closer(last: &NormalizedReceipt) -> String {
    format!(
        "{}: {}.",
        last.created_at.format("%B %-d"),
        last.claim.trim_end_matches('.')
    )
}

/// Build the LLM prompt for the middle receipts (indices 1..n-1).
///
/// The prompt explicitly prohibits the LLM from opening or closing.
/// If `middle` is empty, returns an empty string.
pub fn build_middle_prompt(middle: &[NormalizedReceipt], voice_anchor: &str) -> String {
    if middle.is_empty() {
        return String::new();
    }
    let receipt_lines = middle
        .iter()
        .map(|r| format!("  - {}: {}", r.created_at.format("%B %-d"), r.claim))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "{voice_anchor}\n\n\
         Voice each of the following receipts as a single short sentence in chain order.\n\
         Do NOT write an opening sentence. Do NOT write a closing sentence.\n\
         Those are provided by the substrate. Your output is spliced in the middle only.\n\n\
         Receipts:\n{receipt_lines}",
        voice_anchor = voice_anchor.trim(),
        receipt_lines = receipt_lines,
    )
}

/// Build the full composition for a chain narration from a list of receipts.
///
/// Receipts must be in chain order (oldest first).
/// Returns `None` if `receipts` is empty.
pub fn build_composition(
    receipts: &[NormalizedReceipt],
    voice_anchor: &str,
    llm_provider: &str,
    llm_model: &str,
) -> Option<ChainNarrationComposition> {
    if receipts.is_empty() {
        return None;
    }
    let first = &receipts[0];
    let last = &receipts[receipts.len() - 1];
    let middle = if receipts.len() > 2 {
        &receipts[1..receipts.len() - 1]
    } else if receipts.len() == 2 {
        // Two receipts: opener + closer only, no middle
        &receipts[0..0]
    } else {
        // One receipt: opener IS the closer (no middle, no separate closer)
        &receipts[0..0]
    };

    let opener = format_opener(first);
    let middle_prompt = build_middle_prompt(middle, voice_anchor);
    let closer = if receipts.len() > 1 {
        format_closer(last)
    } else {
        String::new() // Single receipt: opener covers everything
    };

    let receipt_ids: Vec<String> = receipts.iter().map(|r| r.id.clone()).collect();
    let source_manifest = SourceManifest {
        receipt_ids,
        chain_head: last.id.clone(),
    };

    let params_hash = hex::encode(blake3::hash(b"default").as_bytes());
    let render_config = RenderConfig {
        composition_rules_version: COMPOSITION_RULES_VERSION,
        voice_anchor_version: 1,
        render_function_version: RENDER_FUNCTION_VERSION,
        llm_provider: llm_provider.to_string(),
        llm_model: llm_model.to_string(),
        llm_params_hash: params_hash,
    };

    Some(ChainNarrationComposition {
        has_middle: !middle.is_empty(),
        opener,
        middle_prompt,
        closer,
        source_manifest,
        render_config,
    })
}

/// Assemble a chain narration candidate from composition parts + LLM middle text.
///
/// The `llm_middle` is the raw LLM output for the middle receipts.
/// Pass `""` if there are no middle receipts.
///
/// Returns the stored `ArtifactId`.
pub async fn generate_candidate(
    library: &dyn Library,
    composition: ChainNarrationComposition,
    llm_middle: &str,
    operator_id: &str,
    supersedes: Option<ArtifactId>,
) -> Result<ArtifactId, LibraryError> {
    let artifact_id = compute_artifact_id(&composition.source_manifest, &composition.render_config);

    // Assemble the full rendered text from the three structural parts.
    let body = if composition.has_middle && !llm_middle.is_empty() {
        format!(
            "{}\n\n{}\n\n{}",
            composition.opener.trim(),
            llm_middle.trim(),
            composition.closer.trim()
        )
    } else if !composition.closer.is_empty() {
        format!(
            "{}\n\n{}",
            composition.opener.trim(),
            composition.closer.trim()
        )
    } else {
        composition.opener.clone()
    };

    let artifact = Artifact {
        artifact_id: artifact_id.to_hex(),
        kind: ArtifactKind::ChainNarration,
        source_manifest: composition.source_manifest,
        render_config: composition.render_config,
        content: ArtifactContent {
            mime_type: "text/markdown".to_string(),
            body: body.into_bytes(),
        },
        operator_id: operator_id.to_string(),
        generated_at: Utc::now(),
        supersedes: supersedes.map(|id| id.to_hex()),
        lifecycle: LifecycleState::Candidate,
        signature: None,
    };

    library.store_candidate(&artifact).await
}
