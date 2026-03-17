//! ZeroPoint Learning Loop — episode recording and pattern detection.
//!
//! This crate implements the learning loop that powers ZeroPoint's continuous improvement:
//!
//! 1. **Episode Recording**: Every interaction is recorded as an Episode in SQLite
//! 2. **Pattern Detection**: Analyzes episodes to find recurring tool sequences and behaviors
//! 3. **Skill Discovery**: Patterns identified here feed into skill creation and optimization
//!
//! # Example
//!
//! ```no_run
//! use zp_learning::{EpisodeStore, PatternDetector};
//! use zp_core::episode::Episode;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create or open the episode store
//! let store = EpisodeStore::open("episodes.db")?;
//!
//! // Record an episode
//! let episode = unimplemented!("create an Episode");
//! store.record(&episode)?;
//!
//! // Detect patterns
//! let detector = PatternDetector::new();
//! if let Some(pattern) = detector.check(&episode, &store)? {
//!     println!("Pattern found: {}", pattern.description);
//!     println!("Confidence: {}", pattern.confidence);
//! }
//! # Ok(())
//! # }
//! ```

pub mod detector;
pub mod proposal;
pub mod store;

// Re-export the main types for convenience
pub use detector::{PatternDetector, PatternDetectorError, Result as DetectorResult};
pub use proposal::{LearningLoop, ProposalError, ProposalStatus, ProposalStore, SkillProposal};
pub use store::{EpisodeStore, Result as StoreResult, StoreError};

// Re-export commonly used types from zp-core
pub use zp_core::episode::{Episode, EpisodeId, Outcome, Pattern};
