//! Inference backend — local-first LLM calls, with cloud escalation.
//!
//! Every call is governed (W5 3c): the backend never speaks to Ollama or a
//! cloud provider directly. It posts OpenAI-wire-shaped bodies, signed with
//! ZP-Sig, to the substrate's own proxy at
//! `{proxy_base}/api/v1/proxy/{provider}/v1/chat/completions` — the provider
//! segment is `ollama` for local calls (both the local tier and cloud-failure
//! fallback) and the detected cloud provider's name otherwise. The native
//! `/api/chat` path this module spoke pre-3c is retired: the proxy's path
//! allowlist for `ollama` admits only `v1/chat/completions` and `v1/models`,
//! so anything posting `/api/chat` stopped working the moment the endpoint
//! moved to the proxy — this was a protocol retirement, not an endpoint swap.
//!
//! `config.inference_endpoint` still selects the *default* provider exactly
//! as before 3c — `ProviderProfile::detect` runs against it unchanged, a
//! cloud-provider URL substring selects that profile, anything else (no API
//! key) falls through to `ollama()`. What changed is what that selection
//! *feeds*: not a URL to post to, but the `{provider}` path segment. See
//! `InferenceBackend::new` and `chat_via_proxy`.
//!
//! `docs/design/W5-STEP-3C-SESSION-BRIEF.md` and
//! `HARNESS-SEAM-2026-08.md` §6.1.1 carry the full decomposition this
//! module implements.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use zp_core::provider::RequestSigner;

use crate::config::{CloudMandate, RegentConfig};
use crate::error::RegentError;

// ─── Protocol detection ────────────────────────────────────────────

/// Which wire protocol the backend speaks.
#[derive(Debug, Clone, PartialEq)]
pub enum InferenceProtocol {
    /// Ollama HTTP API: /api/chat, /api/tags, /api/ps.
    Ollama,
    /// OpenAI-compatible: /v1/chat/completions (or /chat/completions).
    OpenAI,
}

// ─── Provider-aware auth ──────────────────────────────────────────

/// How to authenticate with the inference endpoint.
///
/// Different providers use different header conventions. The backend
/// auto-detects the strategy from the endpoint URL, or accepts explicit
/// configuration via self_configure. This is data, not code — new
/// providers are a new enum variant, not a new code path.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthStrategy {
    /// No authentication (local Ollama).
    None,
    /// Standard Bearer token: `Authorization: Bearer {key}`.
    /// Used by: OpenAI, Anthropic Messages-compatible proxies, most
    /// OpenAI-compatible endpoints.
    Bearer,
    /// Custom header name: `{header}: {key}`.
    /// Used by: Abacus (`apiKey`), some enterprise proxies.
    Header(String),
}

impl AuthStrategy {
    /// Apply this auth strategy to an HTTP request builder.
    pub fn apply(&self, builder: reqwest::RequestBuilder, key: &str) -> reqwest::RequestBuilder {
        match self {
            AuthStrategy::None => builder,
            AuthStrategy::Bearer => builder.header("Authorization", format!("Bearer {}", key)),
            AuthStrategy::Header(name) => builder.header(name.as_str(), key),
        }
    }
}

/// Provider profile — captures the wire-level differences between
/// inference endpoints. Auto-detected from the endpoint URL or set
/// explicitly. Composes with the model dossier system (Phase 5 of
/// EXECUTION-AUTHORITY-MODEL).
///
/// The design principle: contracts singular (one chat() call site),
/// implementations plural (each provider's auth, URL shape, and
/// response envelope handled by data in the profile, not by branching
/// code paths).
#[derive(Debug, Clone)]
pub struct ProviderProfile {
    /// Human-readable provider name (for logging/receipts).
    pub name: String,
    /// How to authenticate.
    pub auth: AuthStrategy,
    /// Chat endpoint path appended to the base URL.
    /// Examples: "/api/chat" (Ollama), "/v1/chat/completions" (OpenAI).
    pub chat_path: String,
    /// Which response envelope format to expect.
    pub response_format: InferenceProtocol,
}

impl ProviderProfile {
    /// Ollama (local, no auth).
    pub fn ollama() -> Self {
        Self {
            name: "ollama".into(),
            auth: AuthStrategy::None,
            chat_path: "/api/chat".into(),
            response_format: InferenceProtocol::Ollama,
        }
    }

    /// Standard OpenAI-compatible (Bearer auth).
    pub fn openai() -> Self {
        Self {
            name: "openai".into(),
            auth: AuthStrategy::Bearer,
            chat_path: "/v1/chat/completions".into(),
            response_format: InferenceProtocol::OpenAI,
        }
    }

    /// ZeroPoint's own inference proxy.
    ///
    /// Always OpenAI-compatible regardless of which provider sits behind it —
    /// the proxy normalises every backend onto `/v1/chat/completions`, and its
    /// path allowlist admits nothing else for inference.
    ///
    /// `auth` is `None` here and that is a placeholder, not a statement: the
    /// proxy requires a ZP-Sig envelope, which is per-request and body-bound,
    /// so it cannot be expressed as a static `AuthStrategy`. Until the Regent
    /// holds a `GateRequestSigner` (W5 step 3b), calls through this profile
    /// will be rejected with 401 — loudly, which is correct. Fail closed.
    pub fn zp_proxy() -> Self {
        Self {
            name: Self::ZP_PROXY.into(),
            auth: AuthStrategy::None,
            chat_path: "/v1/chat/completions".into(),
            response_format: InferenceProtocol::OpenAI,
        }
    }

    /// Abacus AI / RouteLLM — standard OpenAI-compatible endpoint.
    /// Uses Bearer auth (same as OpenAI), not a custom header.
    /// Supports model routing via the `model` field (e.g. "zai-org/GLM-5.2").
    pub fn abacus() -> Self {
        Self {
            name: "abacus".into(),
            auth: AuthStrategy::Bearer,
            chat_path: "/v1/chat/completions".into(),
            response_format: InferenceProtocol::OpenAI,
        }
    }

    /// Anthropic (x-api-key header, OpenAI-compat response for now).
    /// Note: native Anthropic Messages API uses a different request format;
    /// this profile covers Anthropic-compatible proxies that speak OpenAI wire.
    pub fn anthropic() -> Self {
        Self {
            name: "anthropic".into(),
            auth: AuthStrategy::Header("x-api-key".into()),
            chat_path: "/v1/chat/completions".into(),
            response_format: InferenceProtocol::OpenAI,
        }
    }

    /// The name `zp_proxy()` carries.
    ///
    /// Callers test identity against this rather than re-spelling the
    /// literal, so there is one place the substrate's own proxy is named.
    pub const ZP_PROXY: &'static str = "zp-proxy";

    /// Whether this profile is the substrate's own proxy.
    ///
    /// The proxy is the only endpoint that expects a ZP-Sig envelope; every
    /// other profile authenticates through `AuthStrategy` alone.
    pub fn is_zp_proxy(&self) -> bool {
        self.name == Self::ZP_PROXY
    }

    /// Auto-detect provider from endpoint URL.
    ///
    /// Recognized patterns:
    /// - `*abacus*` or `*routellm*` → Abacus (Bearer auth, OpenAI-compatible)
    /// - `*anthropic*` → Anthropic (x-api-key header)
    /// - `*openai*` or `*together*` or `*groq*` or `*fireworks*` → OpenAI (Bearer)
    /// - `localhost` or `127.0.0.1` without API key → Ollama
    /// - Anything else with API key → OpenAI (safe default)
    pub fn detect(endpoint: &str, has_key: bool) -> Self {
        let lower = endpoint.to_lowercase();

        // ZeroPoint's own proxy, checked first and deliberately.
        //
        // This is not a heuristic like the matches below — it is the substrate
        // recognising its own surface, which is unambiguous and always
        // OpenAI-compatible. It must precede the provider-name matches because
        // a proxy URL carries its backend in the path: `/api/v1/proxy/ollama/`
        // contains "ollama", so the substring rules below would select the
        // native protocol and post to `/api/chat` — a path the proxy allowlist
        // forbids, producing a 400 that reads like a broken backend rather
        // than a misrouted request.
        //
        // Everything after this point remains name-sniffing against
        // third-party endpoints, where declaration is not available. That is a
        // weaker mechanism and should not be extended.
        if lower.contains("/api/v1/proxy/") {
            return Self::zp_proxy();
        }

        if lower.contains("abacus") || lower.contains("routellm") {
            return Self::abacus();
        }
        if lower.contains("anthropic") {
            return Self::anthropic();
        }
        if lower.contains("openai")
            || lower.contains("together")
            || lower.contains("groq")
            || lower.contains("fireworks")
            || lower.contains("deepinfra")
            || lower.contains("perplexity")
        {
            return Self::openai();
        }

        // Local endpoints default to Ollama unless they have an API key.
        if !has_key {
            return Self::ollama();
        }

        // Unknown endpoint with API key → default to Bearer (most common).
        Self::openai()
    }

    /// Build the full chat URL from the base endpoint.
    pub fn chat_url(&self, base_endpoint: &str) -> String {
        let base = base_endpoint.trim_end_matches('/');

        // If the base already ends with the expected path, don't append.
        if base.ends_with("/chat/completions") || base.ends_with("/api/chat") {
            return base.to_string();
        }

        // If base already has /v1 and our path starts with /v1, avoid doubling.
        if base.ends_with("/v1") && self.chat_path.starts_with("/v1/") {
            return format!("{}{}", base, &self.chat_path[3..]);
        }

        format!("{}{}", base, self.chat_path)
    }
}

/// The path a request line will carry, taken from an absolute URL.
///
/// A ZP-Sig envelope binds the path, and the gate recomputes it from the
/// request it received — so this must be exactly what travels: leading `/`,
/// query string included, scheme and authority excluded. A URL with no path
/// yields `/`, which is what an HTTP client sends in that case.
fn request_path(url: &str) -> &str {
    let after_scheme = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    match after_scheme.find('/') {
        Some(i) => &after_scheme[i..],
        None => "/",
    }
}

// ─── Request types ─────────────────────────────────────────────────

/// Inference request — protocol-neutral. Serialized differently
/// depending on which protocol the backend uses.
#[derive(Debug, Clone, Serialize)]
pub struct InferenceRequest {
    /// The model to use.
    pub model: String,
    /// The prompt (system + user messages).
    pub messages: Vec<ChatMessage>,
    /// Optional structured output schema.
    pub format: Option<serde_json::Value>,
    /// Temperature (0.0 = deterministic, 1.0 = creative).
    pub temperature: f32,
    /// Whether to stream the response.
    pub stream: bool,
    /// Ollama options (num_predict, etc.). Ignored for OpenAI protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<serde_json::Value>,
    /// How long to keep the model loaded in memory (Ollama only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive: Option<serde_json::Value>,
    /// Whether to enable thinking mode (qwen3, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub think: Option<bool>,
}

/// A chat message in the Ollama format (also compatible with OpenAI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// What a completed inference call reports about which model served it.
///
/// INFERENCE-ROUTING-DISCIPLINE-2026-07 §Layer 1 opens with "the served
/// model is chain-anchored, always" and names the distinction this type
/// carries: the requested model is what the caller asked for, the served
/// model is what answered, and silent divergence between them is the thing
/// the discipline exists to make structurally impossible.
#[derive(Debug, Clone)]
pub struct ServedModel {
    /// What the caller asked for.
    pub requested: String,
    /// What the backend said it served. `None` means the response carried
    /// no model field — the protocol could not answer. It does **not** mean
    /// the served model matched the request.
    pub served: Option<String>,
}

impl ServedModel {
    /// Best available identity for keying a dossier or baseline lookup.
    ///
    /// Falls back to the requested name when the backend reports none. A
    /// caller that needs to know which of the two it got must ask
    /// [`ServedModel::reported`] rather than infer it from this.
    pub fn effective(&self) -> &str {
        self.served.as_deref().unwrap_or(&self.requested)
    }

    /// Whether the backend actually reported a served model.
    pub fn reported(&self) -> bool {
        self.served.is_some()
    }

    /// Whether the backend served something other than what was requested.
    /// False when nothing was reported — absence is not agreement.
    pub fn diverged(&self) -> bool {
        matches!(&self.served, Some(s) if s != &self.requested)
    }
}

// ─── OpenAI response types ─────────────────────────────────────────

/// Response from OpenAI /v1/chat/completions.
#[derive(Debug, Clone, Deserialize)]
pub struct OpenAIResponse {
    pub choices: Vec<OpenAIChoice>,
    pub usage: Option<OpenAIUsage>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenAIChoice {
    pub message: OpenAIChatMessage,
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenAIChatMessage {
    pub role: String,
    pub content: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenAIUsage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

// ─── Fallback diagnostics ─────────────────────────────────────────

/// Captured when cloud inference fails and the backend falls back to
/// local Ollama. Carries the rejection reason so the Regent (and the
/// chain) can see *why* cloud failed, not just *that* it failed.
#[derive(Debug, Clone, Serialize)]
pub struct FallbackEvent {
    /// The error message from the cloud endpoint (e.g. "403 Forbidden —
    /// {"success": false, "error": "User not logged in"}").
    pub cloud_error: String,
    /// The proxy URL that was called (W5 3c) — computed per call from
    /// `proxy_base` and the provider that was attempted, not a fixed field.
    pub cloud_endpoint: String,
    /// Provider name (e.g. "abacus", "openai", "anthropic").
    pub cloud_provider: String,
    /// Model that was requested from the cloud endpoint.
    pub cloud_model: String,
    /// Model used for fallback inference.
    pub fallback_model: String,
}

// ─── Backend ───────────────────────────────────────────────────────

/// The inference backend — routes every call through the substrate's own
/// governed proxy (W5 3c). Ollama and OpenAI-compatible cloud providers are
/// both reached at `{proxy_base}/api/v1/proxy/{provider}/v1/chat/completions`;
/// the provider segment varies per call, which is why it is a parameter to
/// [`chat_via_proxy`](Self::chat_via_proxy) rather than fixed at construction.
///
/// API key resolution: the backend holds an `ApiKeySource` that indicates
/// *where* the key lives. For `RawLegacy`, the key is in memory (transition
/// path). For `Vault`, the caller must resolve the key from the vault and
/// inject it via `set_resolved_key()` before making calls. The resolved key
/// is held only for the duration of the HTTP call lifecycle — it never enters
/// the Regent's cognitive context, observation pipeline, or chain receipts.
///
/// Pre-3c, `AuthStrategy`/the resolved key were applied on the wire for
/// direct-to-cloud calls. Post-3c every call goes through the proxy and is
/// authenticated solely with ZP-Sig (see `sign_for_gate`); the resolved key
/// is retained for `set_resolved_key`/`set_api_key_source`'s existing
/// call sites and for `ProviderProfile::detect`'s `has_key` input, but no
/// longer travels on the wire itself — the proxy is what talks to the real
/// backend and owns that credential.
pub struct InferenceBackend {
    client: reqwest::Client,
    /// The substrate's own proxy base — e.g. `http://127.0.0.1:17010`, no
    /// path. Supplied at construction (see `new`), not derived from
    /// `config.inference_endpoint`: that field only ever fed
    /// `ProviderProfile::detect`, and under the proxy the actual HTTP target
    /// is built fresh per call from this base plus the provider's name.
    proxy_base: String,
    /// The raw `config.inference_endpoint` string, kept only so
    /// `set_resolved_key`/`set_api_key_source`/`reconfigure` can re-run
    /// `ProviderProfile::detect` against it later — the same string used at
    /// construction, never used to build an HTTP target directly.
    provider_hint: String,
    /// The key source — Vault path, RawLegacy, or None.
    api_key_source: crate::config::ApiKeySource,
    /// Resolved key for the current session. Set by the server layer after
    /// vault resolution; cleared if the source changes. No longer placed on
    /// the wire (see the type doc) — retained because `ProviderProfile::detect`
    /// still keys off `has_key`, and because `resolved_key.is_some()` is part
    /// of what several call sites use to decide whether a cloud provider is
    /// configured at all.
    resolved_key: Option<String>,
    /// Whether the *default* provider is Ollama-shaped (local) or an
    /// OpenAI-shaped cloud provider. Not "which bytes travel on the wire" —
    /// every call is OpenAI-wire-shaped through the proxy now — but "which
    /// provider family `chat()` targets by default", which is exactly what
    /// existing consumers (tier derivation, the hygiene no-ops below) need.
    protocol: InferenceProtocol,
    /// Default provider profile — auto-detected from `config.inference_endpoint`
    /// (a cloud-provider URL, or the local/no-key fallback) exactly as before
    /// 3c. Supplies the `{provider}` path segment `chat_via_proxy` uses for
    /// the default (non-fallback) call.
    provider: ProviderProfile,
    /// Fallback provider — always `ProviderProfile::ollama()`. The local tier
    /// (`chat_local`) and the cloud-failure fallback branch of `chat()` both
    /// reach local Ollama through the same `proxy_base`, at `provider=ollama`,
    /// rather than at a separate direct address. Retired the standalone
    /// `fallback_endpoint` field this replaces (W5 3c §3.9) — there is only
    /// one base now, and the provider segment is what varies.
    fallback_provider: ProviderProfile,
    /// The model to use for fallback inference. Should be a model known
    /// to be available locally (pulled via Ollama).
    fallback_model: String,
    /// Side channel: set when cloud inference fails and fallback fires.
    /// Drained by the cognitive loop after each inference call to emit
    /// a chain receipt. Interior mutability because `chat()` takes `&self`.
    last_fallback: std::sync::Mutex<Option<FallbackEvent>>,
    /// Layer 2 classifier per INFERENCE-ROUTING-DISCIPLINE-2026-07. Runs
    /// on every inference call. Advisory-only in first-shipping: records
    /// which model would have been chosen from the (currently single-
    /// model) envelope and emits `regent:inference:classifier_decision`
    /// receipts. Does NOT alter routing today — that lands when operator
    /// envelope-declaration ceremony ships and envelopes carry multiple
    /// authorized models.
    classifier: std::sync::Arc<dyn crate::inference_classifier::InferenceClassifier + Send + Sync>,
    /// Side channel for the classifier's most recent decision. Same
    /// drain-and-emit pattern as `last_fallback`. Interior mutability
    /// because `chat()` takes `&self`.
    last_classifier_decision:
        std::sync::Mutex<Option<crate::inference_classifier::ClassifierDecision>>,
    /// Which model served the most recently completed call. Same interior-
    /// mutability reason as the two side channels above — `chat()` takes
    /// `&self`. Unlike those, this one is **peeked, not drained**: it answers
    /// "what produced the response I am holding", and a drain would make the
    /// second reader of one response see nothing.
    last_served_model: std::sync::Mutex<Option<ServedModel>>,
    /// Gate-request signer for calls to the substrate's own proxy (W5 3b).
    ///
    /// `None` pre-Genesis, where there is no sovereign root to sign with —
    /// the same shape `gate_signer` already has in `AppState::init`. It is
    /// not configuration and does not live on `RegentConfig`: it is a live
    /// capability handed to the backend, and a `RegentConfig` field would
    /// have to be `#[serde(skip)]`, which is a value that vanishes on a
    /// round-trip without saying so.
    ///
    /// Signs every call `chat_via_proxy` makes (W5 3c). Fail-closed: `None`
    /// still sends the request, unauthenticated, and lets the gate reject it.
    gate_signer: Option<Arc<dyn RequestSigner>>,
}

impl InferenceBackend {
    /// Create from Regent config plus the two live capabilities that cannot
    /// live on `RegentConfig` itself (see the field docs): the gate signer,
    /// and the substrate's own proxy base.
    ///
    /// `default_provider` is still auto-detected from `config.inference_endpoint`
    /// exactly as before 3c — a cloud-provider URL selects that provider's
    /// profile, anything else (including the `@proxy/ollama` sentinel default)
    /// falls through to `ollama()` when no API key is set. What changed in 3c
    /// is what that detection *feeds*: not a URL to post to directly, but the
    /// `{provider}` path segment `chat_via_proxy` appends to `proxy_base`.
    ///
    /// `gate_signer` authenticates every call. Pass `None` pre-Genesis, or
    /// wherever no sovereign root has been loaded; proxy calls made without
    /// it are sent unauthenticated and rejected by the gate, which is the
    /// intended failure — loud, not silent.
    ///
    /// `proxy_base` is the substrate's own address (e.g. `http://127.0.0.1:17010`,
    /// no path) — supplied by the caller, which knows its own listen port,
    /// rather than derived here from a config default that could drift from
    /// it. See `ServerRegentConfig::proxy_base` in `zp-server` for where it is
    /// computed.
    pub fn new(
        config: &RegentConfig,
        gate_signer: Option<Arc<dyn RequestSigner>>,
        proxy_base: String,
    ) -> Self {
        let has_key = config.api_key_source.has_key();
        let provider = ProviderProfile::detect(&config.inference_endpoint, has_key);
        let protocol = provider.response_format.clone();
        let fallback_provider = ProviderProfile::ollama();

        // For RawLegacy, pre-populate the resolved key (transition path).
        let resolved_key = config.api_key_source.raw_key().map(String::from);

        info!(
            proxy_base = %proxy_base,
            provider = %provider.name,
            protocol = ?protocol,
            key_source = ?std::mem::discriminant(&config.api_key_source),
            gate_signer = gate_signer.is_some(),
            "inference backend initialized"
        );

        // Fallback model: use the routing model (smallest available) for
        // degraded-mode inference. If routing == reasoning, fall back to
        // a known-small model that's likely pulled.
        //
        // The "qwen3:1.7b" literal below is intentional, not a discipline
        // violation: this branch exists precisely because
        // config.routing_model has nothing distinct to offer (the operator
        // set routing == reasoning, or left both on the shared default), so
        // deriving from `config.routing_model` here would just hand back
        // the same (potentially large) reasoning model this fallback is
        // meant to avoid, defeating the "degraded-mode, likely-installed,
        // small" intent. This must NOT be swapped for a config-derived
        // value — do not thread ZpConfig.regent_routing_model into this
        // arm.
        let fallback_model = if config.routing_model != config.reasoning_model {
            config.routing_model.clone()
        } else {
            "qwen3:1.7b".to_string()
        };

        Self {
            client: reqwest::Client::new(),
            proxy_base,
            provider_hint: config.inference_endpoint.clone(),
            api_key_source: config.api_key_source.clone(),
            resolved_key,
            protocol,
            provider,
            fallback_provider,
            fallback_model,
            last_fallback: std::sync::Mutex::new(None),
            classifier: std::sync::Arc::new(crate::inference_classifier::DefaultClassifier::new()),
            last_classifier_decision: std::sync::Mutex::new(None),
            last_served_model: std::sync::Mutex::new(None),
            gate_signer,
        }
    }

    /// Inject a vault-resolved API key for the current session.
    ///
    /// Called by the server layer after loading the key from the vault.
    /// The key is held in memory for HTTP calls only — it never enters
    /// the Regent's cognitive context or chain receipts.
    pub fn set_resolved_key(&mut self, key: String) {
        self.resolved_key = Some(key);
        // Re-detect provider now that we have a key (may upgrade from Ollama).
        if self.protocol == InferenceProtocol::Ollama {
            self.provider = ProviderProfile::detect(&self.provider_hint, true);
            self.protocol = self.provider.response_format.clone();
        }
    }

    /// Update the API key source (e.g. after self_configure writes to vault).
    pub fn set_api_key_source(&mut self, source: crate::config::ApiKeySource) {
        self.resolved_key = source.raw_key().map(String::from);
        self.provider = ProviderProfile::detect(&self.provider_hint, source.has_key());
        self.protocol = self.provider.response_format.clone();
        self.api_key_source = source;
    }

    /// The detected (default) provider profile.
    pub fn provider(&self) -> &ProviderProfile {
        &self.provider
    }

    /// The substrate's own proxy base — every call's actual HTTP target.
    /// Named `endpoint` for API continuity; post-3c this is `proxy_base`; see
    /// the field doc for what changed.
    pub fn endpoint(&self) -> &str {
        &self.proxy_base
    }

    /// Which protocol this backend uses.
    pub fn protocol(&self) -> &InferenceProtocol {
        &self.protocol
    }

    /// Drain the last fallback event, if any. Returns `Some` exactly once
    /// per fallback — the caller (cognitive loop) emits a chain receipt and
    /// the event is consumed. Cleared on successful cloud inference.
    pub fn take_fallback_event(&self) -> Option<FallbackEvent> {
        self.last_fallback.lock().ok()?.take()
    }

    /// Drain the last classifier decision, if any. Returns `Some` exactly
    /// once per decision — the caller (cognitive loop) emits a
    /// `regent:inference:classifier_decision:<id>` receipt and the value
    /// is consumed. See INFERENCE-ROUTING-DISCIPLINE-2026-07 §Layer 2.
    pub fn take_classifier_decision(
        &self,
    ) -> Option<crate::inference_classifier::ClassifierDecision> {
        self.last_classifier_decision.lock().ok()?.take()
    }

    /// Which model served the most recently completed call, if any call has
    /// completed. Peeks rather than drains — see the field's doc comment.
    pub fn last_served_model(&self) -> Option<ServedModel> {
        self.last_served_model.lock().ok()?.clone()
    }

    /// Record which model served a call, at the point its response is parsed.
    ///
    /// Called from each protocol's parse site rather than from `chat()`,
    /// because only the protocol layer has seen the response body and the
    /// two protocols report the served model in different places — Ollama at
    /// the response root, OpenAI at `model`.
    fn record_served_model(&self, requested: &str, served: Option<String>) {
        if let Some(ref s) = served {
            if s != requested {
                warn!(
                    requested = %requested,
                    served = %s,
                    "served model diverges from requested — INFERENCE-ROUTING-DISCIPLINE Layer 1"
                );
            }
        }
        if let Ok(mut guard) = self.last_served_model.lock() {
            *guard = Some(ServedModel {
                requested: requested.to_string(),
                served,
            });
        }
    }

    /// Record a classifier decision for the given request. Called at the
    /// entry to every `chat()` invocation. Advisory-only in first-
    /// shipping — the envelope is constructed from the caller's requested
    /// model (single-model envelope), so the decision is always
    /// `SoleAuthorized`. When operator envelope-declaration ceremony ships
    /// and the caller passes a multi-model envelope, this hook flips to
    /// producing meaningful selections without changing its signature.
    fn record_classifier_decision(&self, request: &InferenceRequest) {
        let envelope = crate::inference_classifier::InferenceEnvelope::single(&request.model);
        // Concatenated prompt text for workload classification. Cheap:
        // one allocation over N message bodies.
        let concatenated: String = request
            .messages
            .iter()
            .map(|m| m.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let hint = crate::inference_classifier::QueryHint {
            caller: Some("regent:inference".to_string()),
            prompt_length: Some(concatenated.len()),
            workload_class: crate::inference_classifier::infer_workload_class(&concatenated),
        };
        let decision = self.classifier.choose(&envelope, &hint);
        if let Ok(mut guard) = self.last_classifier_decision.lock() {
            *guard = Some(decision);
        }
    }

    /// Reconfigure the backend at runtime (for self_configure tool).
    ///
    /// API key changes go through the vault — use `set_api_key_source()`
    /// and `set_resolved_key()` instead of passing the key here.
    pub fn reconfigure(&mut self, endpoint: String, model: Option<String>) {
        // Re-detect the default provider from the new hint. `proxy_base` is
        // untouched — it is the substrate's own address, fixed for the
        // process lifetime, not something self_configure changes.
        let has_key = self.resolved_key.is_some();
        self.provider = ProviderProfile::detect(&endpoint, has_key);
        self.protocol = self.provider.response_format.clone();

        info!(
            old_hint = %self.provider_hint,
            new_hint = %endpoint,
            provider = %self.provider.name,
            auth = ?self.provider.auth,
            protocol = ?self.protocol,
            model = ?model,
            "inference backend reconfigured"
        );

        self.provider_hint = endpoint;
    }

    /// Run a chat completion.
    ///
    /// Both arms now call `chat_via_proxy` — the difference retained from the
    /// pre-3c match is *whether cloud-failure fallback wraps the call*, not
    /// which transport is used. When the default provider is Ollama there is
    /// nothing to fall back from; when it is a cloud provider, a fallback-
    /// eligible error degrades to `fallback_provider` (always Ollama) at the
    /// same `proxy_base`.
    pub async fn chat(&self, request: &InferenceRequest) -> Result<String, RegentError> {
        // Layer 2 classifier hook — records a decision for every inference
        // call. Advisory-only today; substrate-observable via the drain
        // path in loop_runner.rs.
        self.record_classifier_decision(request);
        match self.protocol {
            InferenceProtocol::Ollama => self.chat_via_proxy(&self.provider, request).await,
            InferenceProtocol::OpenAI => {
                match self.chat_via_proxy(&self.provider, request).await {
                    Ok(response) => {
                        // Cloud succeeded — clear any prior fallback state.
                        if let Ok(mut fb) = self.last_fallback.lock() {
                            *fb = None;
                        }
                        Ok(response)
                    }
                    Err(ref e) if Self::is_fallback_eligible(e) => {
                        let cloud_error = e.to_string();
                        let cloud_endpoint = self.proxy_url(&self.provider);
                        warn!(
                            provider = %self.provider.name,
                            error = %cloud_error,
                            fallback_provider = %self.fallback_provider.name,
                            fallback_model = %self.fallback_model,
                            "cloud inference failed — degrading to local Ollama fallback"
                        );

                        // Record the fallback event for the cognitive loop to drain.
                        // Per-call now, not read off `self` — the URL that was
                        // actually attempted, not a fixed field (W5 3c §3.5).
                        if let Ok(mut fb) = self.last_fallback.lock() {
                            *fb = Some(FallbackEvent {
                                cloud_error: cloud_error.clone(),
                                cloud_endpoint,
                                cloud_provider: self.provider.name.clone(),
                                cloud_model: request.model.clone(),
                                fallback_model: self.fallback_model.clone(),
                            });
                        }

                        // Build a fallback request with the local model.
                        let mut fallback_request = request.clone();
                        fallback_request.model = self.fallback_model.clone();
                        // Re-enable thinking for local qwen3 models.
                        if self.fallback_model.starts_with("qwen3") {
                            fallback_request.think = Some(false);
                        }
                        match self
                            .chat_via_proxy(&self.fallback_provider, &fallback_request)
                            .await
                        {
                            Ok(response) => Ok(response),
                            Err(ref ollama_err) if Self::is_ollama_not_running(ollama_err) => {
                                // Ollama isn't running — start it and retry once.
                                info!("Ollama not running — starting it for fallback inference");
                                if let Err(start_err) = Self::ensure_ollama_running().await {
                                    warn!("failed to start Ollama: {}", start_err);
                                    return Err(RegentError::Inference(format!(
                                        "cloud inference failed ({}), local fallback unavailable (Ollama not running, auto-start failed: {})",
                                        e, start_err
                                    )));
                                }
                                self.chat_via_proxy(&self.fallback_provider, &fallback_request)
                                    .await
                            }
                            Err(ollama_err) => Err(ollama_err),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Whether a cloud inference error should trigger local fallback.
    ///
    /// Fallback on: auth failures (401, 403), connection errors, timeouts.
    /// Do NOT fallback on: 400 (bad request — our fault), 429 (rate limit —
    /// transient, worth retrying), 5xx (server error — transient).
    ///
    /// Pre-3c, "connection errors" meant this backend's own `reqwest` call
    /// failing to reach a remote host directly, surfaced as `"HTTP error: ..."`
    /// with `connect`/`timeout`/`dns` in the underlying error text. Post-3c
    /// every call reaches the substrate's own loopback proxy — always
    /// reachable — and an unreachable *upstream* provider is reported by the
    /// proxy as a `502` with `"Failed to reach provider"` in the body (see
    /// `zp-server/src/proxy.rs::proxy_handler`), not a `reqwest`-level
    /// connection failure. Both shapes are checked so the fallback still
    /// fires for the failure it was written for.
    fn is_fallback_eligible(error: &RegentError) -> bool {
        let msg = error.to_string();
        // Auth failures — the key is wrong, won't fix itself.
        if msg.contains("401") || msg.contains("403") {
            return true;
        }
        // Connection failures — endpoint is down or unreachable, either at
        // this backend's own client (pre-3c shape) or as a 502 relayed by
        // the proxy after its own upstream call failed (post-3c shape).
        if msg.contains("HTTP error:")
            && (msg.contains("connect") || msg.contains("timeout") || msg.contains("dns"))
        {
            return true;
        }
        if msg.contains("502") || msg.contains("Failed to reach provider") {
            return true;
        }
        false
    }

    /// Whether an error indicates Ollama isn't running.
    ///
    /// See `is_fallback_eligible`'s doc for why both a direct connection
    /// failure and the proxy's 502-relay shape are checked post-3c.
    fn is_ollama_not_running(error: &RegentError) -> bool {
        let msg = error.to_string();
        if msg.contains("502") || msg.contains("Failed to reach provider") {
            return true;
        }
        msg.contains("HTTP error:")
            && (msg.contains("connect") || msg.contains("Connection refused"))
    }

    /// Liveness path for the local inference backend.
    ///
    /// `v1/models`, not the native `api/tags`, and the difference is not
    /// cosmetic. The ZP proxy's allowlist admits only `v1/chat/completions`
    /// and `v1/models` for the ollama provider; the whole `api/*` family is
    /// excluded on purpose, because `api/pull` fetches arbitrary remote
    /// content and `api/delete` mutates local model state, neither of which
    /// belongs behind a forwarding proxy.
    ///
    /// Both surfaces answer the same question — is the backend up and what
    /// does it hold — so probing the OpenAI-compatible one costs nothing and
    /// keeps this call routable once the endpoint moves behind the proxy
    /// (W5 step 3). Probing `api/tags` would 400 there, against a guard that
    /// should not be relaxed to accommodate a health check.
    const LIVENESS_PATH: &'static str = "v1/models";

    /// Raw local Ollama address — direct, unproxied, ungoverned.
    ///
    /// Used only by process/memory-management operations that manage the
    /// *local Ollama process itself* rather than make an inference call:
    /// `ensure_ollama_running`'s own probe (which has its own literal, kept
    /// separate — see that function's doc), and the hygiene no-ops
    /// (`unload_all`, `preload`) plus the model-inventory reads in
    /// `evaluation::discover_local_models` / `awareness::query_loaded_models`.
    /// None of these are chat calls — they read `/api/ps`/`/api/tags` and
    /// post `keep_alive`-only bodies to `/api/chat`, none of which are in the
    /// proxy's `ollama` allowlist (`v1/chat/completions`, `v1/models` only).
    /// That allowlist is deliberate (`api/pull`/`api/delete` must not be
    /// reachable through a forwarding proxy) and is not the thing to relax
    /// to accommodate these — they reach the local process the same way
    /// `ensure_ollama_running` already does, direct and out of the governed
    /// path, same carve-out (W5 3c out-of-scope list).
    pub(crate) const RAW_OLLAMA_BASE_URL: &str = "http://127.0.0.1:11434";

    /// Start Ollama if it's not already running. Waits up to 8 seconds
    /// for the server to become responsive.
    async fn ensure_ollama_running() -> Result<(), String> {
        // Check if already running via a quick health check.
        let client = reqwest::Client::new();
        // zpd:raw-loopback-opt-in -- process-liveness probe, not inference;
        // kept as its own literal rather than reusing RAW_OLLAMA_BASE_URL (see
        // that constant's doc above). W5 3c out-of-scope; W5 step 4 pin opt-in.
        let probe = format!("http://127.0.0.1:11434/{}", Self::LIVENESS_PATH); // zpd:raw-loopback-opt-in
        if client
            .get(&probe)
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
            .is_ok()
        {
            return Ok(());
        }

        // Spawn `ollama serve` as a detached background process.
        // On macOS, `ollama serve` is the standard way to start the server.
        // We also try `open -a Ollama` as fallback (if installed as .app).
        let spawn_result = std::process::Command::new("ollama")
            .arg("serve")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();

        match spawn_result {
            Ok(_child) => {
                info!("spawned `ollama serve` — waiting for it to become responsive");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // `ollama` binary not on PATH — try macOS app launch.
                debug!("ollama binary not found, trying macOS app launch");
                let _ = std::process::Command::new("open")
                    .args(["-a", "Ollama"])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .map_err(|e2| {
                        format!(
                            "neither `ollama serve` nor `open -a Ollama` available: {}, {}",
                            e, e2
                        )
                    })?;
                info!("launched Ollama.app — waiting for it to become responsive");
            }
            Err(e) => {
                return Err(format!("failed to spawn `ollama serve`: {}", e));
            }
        }

        // Poll until responsive (up to 8 seconds, 500ms intervals).
        for _ in 0..16 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if client
                .get(&probe)
                .timeout(std::time::Duration::from_secs(1))
                .send()
                .await
                .is_ok()
            {
                info!("Ollama is now responsive");
                return Ok(());
            }
        }

        Err("Ollama started but not responsive after 8 seconds".to_string())
    }

    /// Attach the ZP-Sig envelope for a request to the substrate's own proxy.
    ///
    /// `body` must be the exact bytes that will be transmitted. The envelope
    /// binds a BLAKE3 hash of them and the gate recomputes that hash over
    /// what it received, so a body serialised twice — once to hash, once to
    /// send — yields a structurally perfect header that fails verification,
    /// reported as `envelope-signature` and indistinguishable from a wrong
    /// key. Callers serialise once and pass those bytes here and to `.body()`.
    ///
    /// Fail closed, never fail open. If no signer is held, or the signer
    /// produces no credential, the request still goes — unauthenticated —
    /// and the gate rejects it. Skipping the call would hide the
    /// misconfiguration; sending it surfaces a 401 that names this backend.
    ///
    /// `method` is a parameter (W5 3c §3.3) because `health_check` and
    /// `model_available` sign `GET`s, not just the `POST`s 3b needed. The
    /// signer normalises case and binds whatever is passed here into the
    /// envelope, so a wrong method here is a clean 401, not a silent pass —
    /// see `zp-gate-envelope`'s `method_is_normalised_to_uppercase`.
    fn sign_for_gate(
        &self,
        builder: reqwest::RequestBuilder,
        method: &str,
        url: &str,
        body: &[u8],
    ) -> reqwest::RequestBuilder {
        let signer = match self.gate_signer.as_ref() {
            Some(s) => s,
            None => {
                warn!(
                    url = %url,
                    "regent holds no gate signer — proxy request will be rejected"
                );
                return builder;
            }
        };

        match signer.authorization(method, request_path(url), body) {
            Some(auth) => builder.header("Authorization", auth),
            None => {
                warn!(
                    url = %url,
                    "gate signer produced no credential — proxy request will be rejected"
                );
                builder
            }
        }
    }

    // ── Governed proxy path (W5 3c) ─────────────────────────────────

    /// Chat via the local tier. Used by the router when a RouteDecision
    /// selects a local model, bypassing the cloud provider entirely.
    /// Reaches Ollama through the same proxy as every other call, at
    /// `provider=ollama` — `fallback_provider` is fixed to that, always.
    pub async fn chat_local(&self, request: &InferenceRequest) -> Result<String, RegentError> {
        // Layer 2 classifier hook — mirrors chat(). See classifier note there.
        self.record_classifier_decision(request);
        match self.chat_via_proxy(&self.fallback_provider, request).await {
            Ok(response) => Ok(response),
            Err(ref e) if Self::is_ollama_not_running(e) => {
                info!("Ollama not running — starting it for local inference");
                if let Err(start_err) = Self::ensure_ollama_running().await {
                    warn!("failed to start Ollama: {}", start_err);
                    return Err(RegentError::Inference(format!(
                        "local inference failed (Ollama not running, auto-start failed: {})",
                        start_err
                    )));
                }
                self.chat_via_proxy(&self.fallback_provider, request).await
            }
            Err(e) => Err(e),
        }
    }

    /// The URL a call to `provider` through this backend's proxy targets.
    /// Shared by `chat_via_proxy` (which sends it) and `chat()`'s fallback
    /// branch (which records it on `FallbackEvent` — a diagnostic read, not
    /// a second call).
    fn proxy_url(&self, provider: &ProviderProfile) -> String {
        format!(
            "{}/api/v1/proxy/{}/v1/chat/completions",
            self.proxy_base.trim_end_matches('/'),
            provider.name
        )
    }

    /// Run a chat completion against `provider`, through this backend's own
    /// proxy. The single call site every public chat method now funnels
    /// through — `chat()` for the default provider and its cloud-failure
    /// fallback, `chat_local()` for the local tier — with `provider` as the
    /// only thing that varies per call (W5 3c §3.5).
    ///
    /// Always OpenAI wire shape, regardless of `provider` — the proxy
    /// normalises every backend onto `/v1/chat/completions` and forwards
    /// accordingly, so there is exactly one request/response shape to build
    /// and parse here, not one per provider. `OllamaResponse` retired with
    /// the native path it parsed (W5 3c §3.7); every response is
    /// `OpenAIResponse`, including the ones served by Ollama.
    ///
    /// Always signed with ZP-Sig, never with `provider.auth` — the proxy is
    /// the authentication boundary for every call now, not a per-provider
    /// header. `provider.auth`/`resolved_key` are not applied to this
    /// request; the proxy is what talks to the real backend and owns that
    /// credential.
    async fn chat_via_proxy(
        &self,
        provider: &ProviderProfile,
        request: &InferenceRequest,
    ) -> Result<String, RegentError> {
        let url = self.proxy_url(provider);

        let input_chars: usize = request.messages.iter().map(|m| m.content.len()).sum();
        debug!(
            model = %request.model,
            messages = request.messages.len(),
            input_chars,
            provider = %provider.name,
            url = %url,
            "regent inference request"
        );

        // Build the OpenAI-wire body. This is the shape `chat_openai` used to
        // build pre-3c, now the only shape — extended to carry the three
        // Ollama-native fields (`options`, `keep_alive`, `think`) through as
        // plain JSON when present. The proxy round-trips the body through
        // `serde_json::Value`, so these survive to a provider that honours
        // them (Ollama's OpenAI-compatible surface) and are harmlessly
        // ignored by one that doesn't.
        //
        // W5 3c §3.6 called for an empirical live check — fire a request
        // with `think: false` against a qwen3 model and confirm no
        // chain-of-thought leaks into `content` — before trusting this
        // pass-through. That check was NOT run in this session: the sandbox
        // this code was written in had no path to the Rust toolchain, so
        // nothing could be built or run. This is the recommended default,
        // implemented; it is not yet confirmed live. Run the probe before
        // relying on `think: false` suppression through the proxy.
        let mut body = serde_json::json!({
            "model": request.model,
            "messages": request.messages.iter().map(|m| {
                serde_json::json!({"role": &m.role, "content": &m.content})
            }).collect::<Vec<_>>(),
            "temperature": request.temperature,
            "stream": false,
        });

        // Add response_format if structured output was requested.
        if let Some(ref fmt) = request.format {
            body["response_format"] = serde_json::json!({
                "type": "json_object"
            });
            // Some providers support json_schema; for now use json_object
            // which is universally supported and sufficient for intent parsing.
            let _ = fmt; // acknowledge but don't use the full schema yet
        }
        if let Some(ref options) = request.options {
            body["options"] = options.clone();
        }
        if let Some(ref keep_alive) = request.keep_alive {
            body["keep_alive"] = keep_alive.clone();
        }
        if let Some(think) = request.think {
            body["think"] = serde_json::Value::Bool(think);
        }

        let t0 = std::time::Instant::now();

        // Serialize ONCE and transmit exactly these bytes — see `sign_for_gate`.
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| RegentError::Inference(format!("request serialization failed: {}", e)))?;

        let req = self
            .client
            .post(&url)
            .header("Content-Type", "application/json");
        let req = self.sign_for_gate(req, "POST", &url, &body_bytes);

        let resp = req
            .body(body_bytes)
            .send()
            .await
            .map_err(|e| RegentError::Inference(format!("HTTP error: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            return Err(RegentError::Inference(format!(
                "inference failed: {} — {}",
                status, err_body
            )));
        }

        let raw_body = resp
            .text()
            .await
            .map_err(|e| RegentError::Inference(format!("body read error: {}", e)))?;

        info!(
            raw_len = raw_body.len(),
            raw_preview = %crate::text::preview(&raw_body, 500),
            "regent raw proxy response"
        );

        let openai_resp: OpenAIResponse = serde_json::from_str(&raw_body).map_err(|e| {
            RegentError::Inference(format!(
                "parse error: {} — body: {}",
                e,
                crate::text::preview(&raw_body, 200)
            ))
        })?;

        self.record_served_model(&request.model, openai_resp.model.clone());

        let content = openai_resp
            .choices
            .first()
            .and_then(|c| c.message.content.clone())
            .unwrap_or_default();

        // Same leak check `chat_ollama_at` used to run — still meaningful:
        // `think: false` suppressing chain-of-thought is a content-shape
        // guarantee, not a transport one, and this is the one place left
        // that would notice it silently stop holding.
        if content.contains("<think>") || content.contains("</think>") {
            warn!(
                model = %request.model,
                think_setting = ?request.think,
                content_len = content.len(),
                "think tags leaked into content — model not suppressing CoT"
            );
        }

        let elapsed_ms = t0.elapsed().as_millis() as u64;
        let prompt_tokens = openai_resp
            .usage
            .as_ref()
            .and_then(|u| u.prompt_tokens)
            .unwrap_or(0);
        let completion_tokens = openai_resp
            .usage
            .as_ref()
            .and_then(|u| u.completion_tokens)
            .unwrap_or(0);
        let model_used = openai_resp.model.as_deref().unwrap_or("unknown");

        info!(
            elapsed_ms,
            prompt_tokens,
            completion_tokens,
            model = model_used,
            provider = %provider.name,
            output_len = content.len(),
            "regent inference completed (proxy)"
        );

        Ok(content)
    }

    // ── Ollama-specific ops (no-op on OpenAI) ──────────────────────

    /// Unload all currently loaded models from Ollama.
    /// No-op for OpenAI protocol (cloud models don't have memory management).
    ///
    /// Reaches the raw local Ollama process directly (`RAW_OLLAMA_BASE_URL`),
    /// not through the proxy — this manages the process's own memory, not an
    /// inference call, and `/api/ps` plus a `keep_alive`-only `/api/chat`
    /// post are both outside the proxy's `ollama` allowlist. See that
    /// constant's doc for the full reasoning; same carve-out as
    /// `ensure_ollama_running`.
    pub async fn unload_all(&self) {
        if self.protocol != InferenceProtocol::Ollama {
            debug!("inference hygiene: skipping unload (not Ollama)");
            return;
        }

        let ps_url = format!("{}/api/ps", Self::RAW_OLLAMA_BASE_URL);
        let loaded: Vec<String> = match self.client.get(&ps_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                body["models"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|m| m["name"].as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default()
            }
            _ => {
                debug!("inference hygiene: Ollama unreachable, skipping unload");
                return;
            }
        };

        if loaded.is_empty() {
            debug!("inference hygiene: no models loaded, nothing to unload");
            return;
        }

        let chat_url = format!("{}/api/chat", Self::RAW_OLLAMA_BASE_URL);
        for model in &loaded {
            let body = serde_json::json!({
                "model": model,
                "messages": [],
                "keep_alive": 0,
                "stream": false,
            });

            match self.client.post(&chat_url).json(&body).send().await {
                Ok(resp) if resp.status().is_success() => {
                    info!(
                        model = model.as_str(),
                        "inference hygiene: unloaded stale model"
                    );
                }
                Ok(resp) => {
                    let status = resp.status();
                    warn!(model = model.as_str(), %status, "inference hygiene: unload failed");
                }
                Err(e) => {
                    warn!(model = model.as_str(), error = %e, "inference hygiene: unload failed");
                }
            }
        }

        info!(
            count = loaded.len(),
            "inference hygiene: cleared stale models"
        );
    }

    /// Preload models into memory (Ollama only).
    /// No-op for OpenAI protocol.
    ///
    /// Direct to `RAW_OLLAMA_BASE_URL`, same reasoning as `unload_all`: a
    /// `keep_alive`-only post to `/api/chat` isn't in the proxy's allowlist,
    /// and this is process memory management, not a governed inference call.
    pub async fn preload(&self, models: &[&str]) {
        if self.protocol != InferenceProtocol::Ollama {
            debug!("preload: skipping (not Ollama — cloud models are always ready)");
            return;
        }

        let url = format!("{}/api/chat", Self::RAW_OLLAMA_BASE_URL);
        for model in models {
            info!(model, "preloading model into memory");
            let t0 = std::time::Instant::now();

            let body = serde_json::json!({
                "model": model,
                "messages": [],
                "keep_alive": -1,
                "stream": false,
            });

            match self.client.post(&url).json(&body).send().await {
                Ok(resp) if resp.status().is_success() => {
                    info!(
                        model,
                        elapsed_ms = t0.elapsed().as_millis() as u64,
                        "model preloaded"
                    );
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    warn!(model, %status, body, "model preload failed");
                }
                Err(e) => {
                    warn!(model, error = %e, "model preload failed");
                }
            }
        }
    }

    /// The URL a liveness probe (`LIVENESS_PATH`) against `provider` targets,
    /// through this backend's proxy. Shared by `health_check` and
    /// `model_available` — both ask the same surface the same question.
    fn liveness_url(&self, provider: &ProviderProfile) -> String {
        format!(
            "{}/api/v1/proxy/{}/{}",
            self.proxy_base.trim_end_matches('/'),
            provider.name,
            Self::LIVENESS_PATH
        )
    }

    /// Check if the inference backend is reachable.
    ///
    /// Unified across providers (W5 3c §3.2) — the guard this used to branch
    /// on (`self.protocol`) was keying "which response shape to expect" to
    /// "which wire path to probe", and those diverged the moment the default
    /// provider's calls started going through the same proxy surface as
    /// everyone else's. `detect()` no longer decides which branch runs here;
    /// there is one branch, and it asks whichever provider is configured.
    ///
    /// Pre-3c this had a stale comment claiming a proxy URL still resolved
    /// to the Ollama arm below — false since 3a, when `detect()` started
    /// checking the `/api/v1/proxy/` prefix first and returning `zp_proxy()`
    /// (OpenAI-shaped). That divergence is what this unification removes.
    pub async fn health_check(&self) -> Result<bool, RegentError> {
        let url = self.liveness_url(&self.provider);
        let req = self.client.get(&url);
        let req = self.sign_for_gate(req, "GET", &url, b"");
        match req.send().await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(_) => Ok(false),
        }
    }

    /// Check if a specific model is available.
    ///
    /// Pre-3c this returned `Ok(true)` unconditionally whenever
    /// `self.protocol != InferenceProtocol::Ollama` — under a proxy endpoint,
    /// `detect()` already returns the OpenAI-shaped `zp_proxy()` profile, so
    /// that guard fired for every model regardless of whether it was
    /// actually available, silently defeating the `v1/models` migration this
    /// probe took specifically so it would keep answering honestly once the
    /// endpoint moved (W5 3c §3.1). The guard keyed on wire protocol; what
    /// matters is whether the target can answer the question, and the
    /// `ollama` provider through the proxy can, same as it always could
    /// directly. There is no protocol-based early return any more — every
    /// provider gets asked, and the two-shape parser below (already present)
    /// handles whichever one answers.
    pub async fn model_available(&self, model: &str) -> Result<bool, RegentError> {
        let url = self.liveness_url(&self.provider);
        let req = self.client.get(&url);
        let req = self.sign_for_gate(req, "GET", &url, b"");
        let resp = req
            .send()
            .await
            .map_err(|e| RegentError::Inference(format!("HTTP error: {}", e)))?;

        if !resp.status().is_success() {
            return Ok(false);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| RegentError::Inference(format!("parse error: {}", e)))?;

        // Accept either shape. `data[].id` is the OpenAI-compatible surface
        // (and what the proxy forwards); `models[].name` is the native one,
        // retained so a directly-configured backend still answers correctly.
        // Absence of both is reported as "not available" rather than an error,
        // matching the prior behaviour on a malformed body.
        let matches_name = |n: &str| n.starts_with(model);

        let available = body["data"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .any(|m| m["id"].as_str().is_some_and(matches_name))
            })
            .or_else(|| {
                body["models"].as_array().map(|entries| {
                    entries
                        .iter()
                        .any(|m| m["name"].as_str().is_some_and(matches_name))
                })
            })
            .unwrap_or(false);

        Ok(available)
    }

    /// Validate that a CloudMandate is active before escalation.
    pub fn validate_mandate(
        mandate: &Option<CloudMandate>,
        estimated_tokens: u64,
    ) -> Result<(), RegentError> {
        match mandate {
            None => Err(RegentError::InsufficientDelegation {
                action: "cloud escalation requires an active mandate".to_string(),
            }),
            Some(m) if !m.is_active() => Err(RegentError::InsufficientDelegation {
                action: "cloud mandate expired or exhausted".to_string(),
            }),
            Some(m) if m.remaining() < estimated_tokens => {
                Err(RegentError::InsufficientDelegation {
                    action: format!(
                        "cloud mandate has {} tokens remaining, need {}",
                        m.remaining(),
                        estimated_tokens
                    ),
                })
            }
            Some(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod detect_tests {
    use super::*;

    const PROXY: &str = "http://127.0.0.1:17010/api/v1/proxy/ollama/v1/chat/completions";

    /// The regression this guards: a proxy URL carries its backend in the
    /// path, so `/proxy/ollama/` substring-matches the local-endpoint rule and
    /// selects the native Ollama protocol. That posts to `/api/chat`, which the
    /// proxy allowlist forbids — a 400 that reads like a broken backend rather
    /// than a misrouted request.
    #[test]
    fn zp_proxy_is_recognised_despite_provider_in_path() {
        let p = ProviderProfile::detect(PROXY, false);
        assert_eq!(p.name, "zp-proxy");
        assert_eq!(p.response_format, InferenceProtocol::OpenAI);
        assert_eq!(p.chat_path, "/v1/chat/completions");
    }

    /// Proxy recognition must not depend on whether a key happens to be set.
    #[test]
    fn zp_proxy_recognised_with_or_without_key() {
        assert_eq!(ProviderProfile::detect(PROXY, true).name, "zp-proxy");
        assert_eq!(ProviderProfile::detect(PROXY, false).name, "zp-proxy");
    }

    /// A cloud provider behind the proxy is still the proxy's wire format —
    /// the substrate's own surface wins over the provider name in the path.
    #[test]
    fn proxy_wins_over_provider_name_in_path() {
        let url = "http://127.0.0.1:17010/api/v1/proxy/anthropic/v1/chat/completions";
        assert_eq!(ProviderProfile::detect(url, true).name, "zp-proxy");
    }

    /// A directly-configured backend is unaffected.
    #[test]
    fn direct_ollama_still_detects_as_ollama() {
        // zpd:raw-loopback-opt-in -- test fixture, not a call site: asserts
        // detect() recognizes a raw-Ollama-shaped URL.
        let p = ProviderProfile::detect("http://127.0.0.1:11434", false); // zpd:raw-loopback-opt-in
        assert_eq!(p.name, "ollama");
        assert_eq!(p.response_format, InferenceProtocol::Ollama);
    }

    /// Third-party name-sniffing is unchanged.
    #[test]
    fn third_party_detection_is_unchanged() {
        assert_eq!(
            ProviderProfile::detect("https://api.openai.com", true).name,
            "openai"
        );
        assert_eq!(
            ProviderProfile::detect("https://routellm.abacus.ai/v1", true).name,
            "abacus"
        );
        assert_eq!(
            ProviderProfile::detect("https://api.anthropic.com", true).name,
            "anthropic"
        );
    }

    /// The proxy chat path is already complete, so `chat_url` must not append.
    #[test]
    fn chat_url_leaves_a_complete_proxy_url_alone() {
        let p = ProviderProfile::zp_proxy();
        assert_eq!(p.chat_url(PROXY), PROXY);
    }

    // ── W5 3b: gate-envelope signing surface ───────────────────────

    /// `is_zp_proxy` is the predicate the signing condition reads. It must
    /// agree with `detect` on the URL shape and disagree on every other.
    #[test]
    fn is_zp_proxy_matches_detection() {
        assert!(ProviderProfile::zp_proxy().is_zp_proxy());
        assert!(ProviderProfile::detect(PROXY, false).is_zp_proxy());
        // zpd:raw-loopback-opt-in -- test fixture, not a call site.
        assert!(!ProviderProfile::detect("http://127.0.0.1:11434", false).is_zp_proxy()); // zpd:raw-loopback-opt-in
        assert!(!ProviderProfile::detect("https://api.openai.com", true).is_zp_proxy());
    }

    /// The envelope binds the path, and the gate recomputes it from the
    /// request line — so this must be exactly what travels. A wrong path
    /// produces a structurally perfect header that fails verification,
    /// reported as `envelope-signature` and indistinguishable from a bad key.
    #[test]
    fn request_path_is_what_travels() {
        assert_eq!(
            request_path(PROXY),
            "/api/v1/proxy/ollama/v1/chat/completions"
        );
        // zpd:raw-loopback-opt-in -- test fixture, not a call site.
        assert_eq!(request_path("http://127.0.0.1:11434/api/chat"), "/api/chat"); // zpd:raw-loopback-opt-in
        assert_eq!(request_path("https://host/v1/models?a=1"), "/v1/models?a=1");
    }

    /// A URL with no path yields `/` — what an HTTP client sends in that case.
    #[test]
    fn request_path_defaults_to_root() {
        assert_eq!(request_path("http://127.0.0.1:17010"), "/");
        assert_eq!(request_path("http://127.0.0.1:17010/"), "/");
    }

    /// The scheme's own `//` must not be mistaken for the start of the path.
    #[test]
    fn request_path_skips_the_scheme() {
        assert_eq!(request_path("https://example.com/a/b"), "/a/b");
    }
}
