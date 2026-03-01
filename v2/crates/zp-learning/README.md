# zp-learning — ZeroPoint Learning Loop

Episode recording and pattern detection for continuous learning and skill discovery.

## Overview

The learning loop is how ZeroPoint improves over time. Every interaction is recorded as an **Episode** (conversation, request, tools used, outcome), and the system analyzes these episodes to detect **Patterns** — recurring sequences of tool use that can be optimized into Skills.

## Components

### EpisodeStore

Persistent SQLite-based storage for episodes with querying capabilities.

**Key Features:**
- Records episodes with full context (conversation ID, timestamp, tools used, outcome)
- Efficient retrieval by ID, category, conversation, or recency
- Indexed queries for fast lookups on large datasets
- Cleanup operations for retention policies

**API:**
```rust
pub fn record(&self, episode: &Episode) -> Result<()>
pub fn get(&self, id: &EpisodeId) -> Result<Option<Episode>>
pub fn recent(&self, limit: usize) -> Result<Vec<Episode>>
pub fn by_category(&self, category: &str, limit: usize) -> Result<Vec<Episode>>
pub fn by_conversation(&self, conversation_id: &str, limit: usize) -> Result<Vec<Episode>>
pub fn count(&self) -> Result<usize>
pub fn delete_older_than_days(&self, days: i64) -> Result<usize>
```

**Storage Schema:**
```sql
CREATE TABLE episodes (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    request_category TEXT NOT NULL,
    data TEXT NOT NULL  -- Full episode serialized as JSON
)
```

Indexes are created on `conversation_id`, `timestamp`, and `request_category` for efficient querying.

### PatternDetector

Detects recurring patterns across episodes for skill discovery.

**Algorithm (Phase 1):**
1. Groups recent episodes by their tool sequence (the names of tools called in order)
2. Counts how many episodes share the same sequence
3. If count ≥ threshold (default 3), a pattern is detected
4. Confidence is calculated as: `min(occurrence_ratio * 0.9, 0.95)`
5. Returns patterns sorted by confidence (highest first)

**Key Features:**
- Configurable minimum occurrence threshold
- Confidence scoring based on frequency and consistency
- Separate analysis methods for single episodes and entire categories
- Full audit trail (which episodes contributed to a pattern)

**API:**
```rust
pub fn check(&self, episode: &Episode, store: &EpisodeStore) -> Result<Option<Pattern>>
pub fn analyze_category(&self, category: &str, store: &EpisodeStore) -> Result<Vec<Pattern>>
pub fn with_min_occurrences(min_occurrences: usize) -> Self
```

## Usage Example

```rust
use zp_learning::{EpisodeStore, PatternDetector};

// Create or open the episode store
let store = EpisodeStore::open("episodes.db")?;

// Record an episode (typically done by the pipeline after each interaction)
store.record(&episode)?;

// Detect patterns in the episode
let detector = PatternDetector::new();
if let Some(pattern) = detector.check(&episode, &store)? {
    println!("Pattern found: {}", pattern.description);
    println!("Confidence: {}", pattern.confidence);
    println!("Occurrences: {}", pattern.occurrence_count);
    
    // Pattern can be used to create or optimize a Skill
    // (handled by zp-skills crate)
}

// Analyze entire category
let patterns = detector.analyze_category("document_processing", &store)?;
for pattern in patterns {
    println!("{}: {} (confidence: {})", 
             pattern.description, 
             pattern.tool_sequence.join(" -> "),
             pattern.confidence);
}
```

## Data Model

### Episode
Represents one complete interaction cycle. Contains:
- Unique ID and conversation context
- Request category (e.g., "search", "analysis", "document_processing")
- Sequence of tools called
- Active skills during execution
- Model used
- Outcome (Success, Failure, or Partial)
- Duration and feedback (optional)

### Pattern
A detected recurring sequence. Contains:
- List of episode IDs that contributed to the pattern
- Tool sequence (ordered list of tool names)
- Confidence score (0.0 to 1.0)
- Occurrence count and description

## Phase 1 Implementation

This is a straightforward, production-ready implementation suitable for Phase 1:

**Strengths:**
- Simple, understandable algorithm
- Efficient SQL queries with proper indexing
- Fast detection without complex analysis
- Good baseline for pattern identification

**Future Enhancements (Phase 2+):**
- Tool argument patterns (not just tool names)
- Temporal analysis (patterns that occur at specific times)
- Success correlation (patterns that correlate with successful outcomes)
- Skill effectiveness tracking
- Automatic skill refinement based on pattern changes
- Machine learning for confidence scoring

## Testing

All modules include comprehensive unit tests:

```bash
cargo test -p zp-learning
```

**Test Coverage:**
- Episode recording and retrieval
- Query operations (recent, by_category, by_conversation)
- Pattern detection at different thresholds
- Confidence calculation
- Category analysis with multiple patterns

## Integration Points

**Upstream (episode sources):**
- `zp-pipeline`: Records episodes after each interaction
- `zp-audit`: May enrich episodes with audit information

**Downstream (pattern consumers):**
- `zp-skills`: Creates or refines skills based on detected patterns
- `zp-policy`: May adjust policy decisions based on pattern insights
- `zp-server`: Provides learning analytics via API

## Error Handling

Three main error types:

1. **StoreError**: Database operations (I/O, serialization, data integrity)
2. **PatternDetectorError**: Detection logic failures
3. Both implement `thiserror::Error` for ergonomic `?` propagation

## Database Persistence

The store uses SQLite with:
- **WAL mode**: Enables better concurrency for read-heavy workloads
- **STRICT tables**: Type safety at the schema level
- **Indexes**: Fast lookups on common query patterns
- **Text timestamps**: ISO 8601 format for portability

The database file path is configurable, allowing flexible deployment options (single file, in-memory for tests, etc.)

## Performance Characteristics

- **Record episode**: O(1) + I/O (single row insert)
- **Get by ID**: O(log n) with index
- **Recent N episodes**: O(log n + N) with indexed sort
- **By category N episodes**: O(log n + N) with indexed filter
- **Pattern detection**: O(N log N) for N recent episodes (dominated by sorting)
- **Category analysis**: O(M log M) for M category episodes

All operations are I/O bound on SQLite, not CPU bound.

## Configuration

Create via `EpisodeStore::open(path)` with sensible defaults:
- Min occurrences for patterns: 3
- Retention: Application-dependent (use `delete_older_than_days` as needed)
- Category cardinality: Unbounded (arbitrary strings)

Future versions may add config files for centralized settings.
