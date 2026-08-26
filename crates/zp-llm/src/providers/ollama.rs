//! `OllamaProvider` deleted 2026-08-25 (dead code -- never instantiated
//! outside its own file/tests; confirmed by workspace grep before and
//! after this change; consumers found were markdown docs only, not
//! compiled/doctested code -- see the session report). Removed from the
//! module tree in `providers/mod.rs`. Ken's decision, following the
//! no_raw_provider_http_outside_canonical_layer_loopback pin finding it.
//!
//! This file could not be physically removed from this sandbox --
//! `rm`, `os.unlink`, and `git rm` were all denied by the mount
//! (`Operation not permitted`) -- so its content was emptied instead,
//! which is also what gets the discipline pin itself to a clean pass:
//! the pin walks the filesystem directly, not the crate's module graph,
//! so disconnecting `mod ollama;` alone left the literal strings on
//! disk for the pin to keep finding.
//!
//! Ken: `rm crates/zp-llm/src/providers/ollama.rs` to finish the cleanup
//! -- nothing references this file any more.
