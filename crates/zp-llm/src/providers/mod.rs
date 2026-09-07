//! LLM provider implementations.

pub mod anthropic;
// `mod ollama` removed 2026-08-25: OllamaProvider was dead code (never
// instantiated outside its own file/tests -- confirmed by workspace grep
// before and after this change). Deleted from the module tree per Ken's
// decision on the no_raw_provider_http_outside_canonical_layer_loopback
// pin's finding. crates/zp-llm/src/providers/ollama.rs itself could not be
// physically removed from this sandbox (rm/unlink/git rm all denied by the
// mount) -- it is orphaned on disk, uncompiled, and safe to `rm` by hand.
pub mod proxy;

#[allow(deprecated)]
pub use anthropic::AnthropicProvider;
pub use proxy::ProxyLlmProvider;
