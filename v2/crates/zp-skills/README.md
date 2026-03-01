# zp-skills

Skill registry and keyword-based matcher for ZeroPoint v2.

A skill is a reusable unit of behavior — a named bundle of tools, keywords, and a prompt template that the pipeline activates when a request matches. This crate manages skill registration, lifecycle tracking, and request matching.

## Modules

### registry.rs — SkillRegistry

Central manager for all registered skills. Thread-safe via `parking_lot::RwLock`.

`RegisteredSkill` combines a `SkillManifest` (from zp-core), a `SkillOrigin` (BuiltIn, Extracted, Community, Enterprise), runtime `SkillStats`, and an enabled flag.

Key methods: `register()` adds a new skill (fails on duplicate ID), `unregister()` removes one, `get()` retrieves by ID, `list()` returns all skills, `enable()`/`disable()` toggle matching availability, `update_stats()` records execution results (invocation count, success/failure, exponential moving average latency, last-used timestamp), and `skill_count()`/`enabled_count()` for inventory.

### matcher.rs — SkillMatcher

Stateless keyword-based matching. `match_request()` takes a registry reference and request text, then:

1. Tokenizes the request: lowercase, split on non-alphanumeric characters (preserving underscores), filter empties
2. Scores each enabled skill: for every skill keyword and every request token, if either contains the other, increment the match count
3. Sorts by match count (descending), then by skill ID (alphabetical) for deterministic ordering
4. Returns the ranked list of `SkillId` values

Matching is case-insensitive and supports partial words — "send" matches keyword "sending", "mail" matches "mailing". Disabled skills are excluded.

This is Phase 1 matching. Semantic matching with embeddings is planned for future phases.
