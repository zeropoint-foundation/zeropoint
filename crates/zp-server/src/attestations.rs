//! Attestation and analytics system for ZeroPoint course completions.
//!
//! Two subsystems live here:
//!
//! **Attestations** — Signed, hash-linked completion records stored in SQLite.
//! Each attestation is a receipt: it records who completed what course, when,
//! and is signed by the server's Ed25519 identity. Attestations chain to each
//! other (each references the previous attestation's hash), forming a tamper-
//! evident ledger of all issued certifications. The visual certificate at
//! zeropoint.global/verify renders these records.
//!
//! **Anonymous Analytics** — Aggregate course improvement data with no identity
//! linkage. The course app fires events (module started, module completed) with
//! a random per-session token. The analytics endpoint returns only aggregate
//! stats: per-module start/completion counts, completion rates, and median
//! durations. No individual learning paths are exposed. This gives course
//! authors the data they need to improve the material without surveilling
//! learners — philosophically consistent with ZeroPoint's stance on sovereignty.

use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use ed25519_dalek::Signer as DalekSigner;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::AppState;
use axum::extract::Query;

// ============================================================================
// Types
// ============================================================================

#[derive(Deserialize)]
pub struct IssueAttestationRequest {
    /// Full name of the builder
    pub name: String,
    /// Track identifier (e.g., "track-2-builder")
    pub track: String,
    /// Module completion timestamps (module_id -> ISO 8601 timestamp)
    pub completions: Vec<ModuleCompletion>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ModuleCompletion {
    pub module_id: u32,
    pub module_name: String,
    pub completed_at: String,
}

#[derive(Serialize, Clone)]
pub struct Attestation {
    /// Unique attestation ID (e.g., "ZP-ATT-2026-A3F2")
    pub id: String,
    /// Builder name
    pub name: String,
    /// Track completed
    pub track: String,
    /// Number of modules completed
    pub modules_completed: u32,
    /// Module completion details
    pub completions: Vec<ModuleCompletion>,
    /// ISO 8601 timestamp of issuance
    pub issued_at: String,
    /// Blake3 hash of the canonical attestation content
    pub attestation_hash: String,
    /// Ed25519 signature (hex) of the attestation hash
    pub signature: String,
    /// Public key of the signing server (hex)
    pub signer_public_key: String,
    /// Epoch number (weeks since 2026-01-01)
    pub epoch: u64,
    /// Previous attestation hash (chain linkage)
    pub prev_attestation_hash: Option<String>,
}

#[derive(Serialize)]
pub struct AttestationSummary {
    pub id: String,
    pub name: String,
    pub track: String,
    pub modules_completed: u32,
    pub issued_at: String,
    pub attestation_hash: String,
    pub verified: bool,
}

#[derive(Deserialize)]
pub struct LookupQuery {
    pub id: Option<String>,
}

// ============================================================================
// SQLite Schema
// ============================================================================

/// Initialize the attestations table. Call once at server startup.
pub fn init_attestation_db(data_dir: &str) -> rusqlite::Result<()> {
    let db_path = format!("{}/attestations.db", data_dir);
    let conn = rusqlite::Connection::open(&db_path)?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS attestations (
            id                    TEXT PRIMARY KEY,
            name                  TEXT NOT NULL,
            track                 TEXT NOT NULL,
            modules_completed     INTEGER NOT NULL,
            completions_json      TEXT NOT NULL,
            issued_at             TEXT NOT NULL,
            attestation_hash      TEXT NOT NULL UNIQUE,
            signature             TEXT NOT NULL,
            signer_public_key     TEXT NOT NULL,
            epoch                 INTEGER NOT NULL,
            prev_attestation_hash TEXT,
            created_at            TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_attestations_hash
            ON attestations(attestation_hash);
        CREATE INDEX IF NOT EXISTS idx_attestations_name
            ON attestations(name);
        CREATE INDEX IF NOT EXISTS idx_attestations_track
            ON attestations(track);

        -- Anonymous course analytics: no name, no identity, no linkage to attestations.
        -- Each row is a single module event. The session_id is a random token
        -- generated client-side per browser session — not linked to any user identity.
        CREATE TABLE IF NOT EXISTS course_analytics (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      TEXT NOT NULL,
            track           TEXT NOT NULL,
            module_id       INTEGER NOT NULL,
            event           TEXT NOT NULL,
            duration_secs   INTEGER,
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_analytics_track_module
            ON course_analytics(track, module_id);
        CREATE INDEX IF NOT EXISTS idx_analytics_event
            ON course_analytics(event);",
    )?;

    Ok(())
}

// ============================================================================
// Anonymous Analytics Types
// ============================================================================

#[derive(Deserialize)]
pub struct AnalyticsEvent {
    /// Random session token (generated client-side, not linked to identity)
    pub session_id: String,
    /// Track identifier
    pub track: String,
    /// Module number
    pub module_id: u32,
    /// Event type: "started", "completed", "checkpoint_started", "checkpoint_completed"
    pub event: String,
    /// Time spent in seconds (optional, for "completed" events)
    pub duration_secs: Option<u32>,
}

#[derive(Serialize)]
pub struct ModuleAnalytics {
    pub module_id: u32,
    pub starts: u64,
    pub completions: u64,
    pub completion_rate: f64,
    pub median_duration_secs: Option<u64>,
    pub checkpoint_starts: u64,
    pub checkpoint_completions: u64,
}

#[derive(Serialize)]
pub struct CourseAnalytics {
    pub track: String,
    pub total_sessions: u64,
    pub full_completions: u64,
    pub modules: Vec<ModuleAnalytics>,
}

// ============================================================================
// Helpers
// ============================================================================

/// Generate a deterministic attestation ID from name + timestamp.
fn generate_attestation_id(name: &str, timestamp: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(b"zeropoint-attestation");
    let hash = hasher.finalize();
    let suffix = hex::encode(&hash[..2]).to_uppercase();
    let year = &timestamp[..4];
    format!("ZP-ATT-{}-{}", year, suffix)
}

/// Compute the canonical hash of an attestation's content.
fn compute_attestation_hash(
    id: &str,
    name: &str,
    track: &str,
    modules_completed: u32,
    issued_at: &str,
    prev_hash: &Option<String>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update(b"|");
    hasher.update(name.as_bytes());
    hasher.update(b"|");
    hasher.update(track.as_bytes());
    hasher.update(b"|");
    hasher.update(modules_completed.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(issued_at.as_bytes());
    hasher.update(b"|");
    if let Some(prev) = prev_hash {
        hasher.update(prev.as_bytes());
    } else {
        hasher.update(b"genesis");
    }
    hex::encode(hasher.finalize())
}

/// Compute the current epoch (weeks since 2026-01-01).
fn current_epoch() -> u64 {
    let epoch_start = chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc();
    let now = Utc::now();
    let duration = now.signed_duration_since(epoch_start);
    (duration.num_weeks().max(0) as u64) + 1
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /api/v1/attestations — Issue a new attestation.
pub async fn issue_attestation_handler(
    State(state): State<AppState>,
    Json(req): Json<IssueAttestationRequest>,
) -> Result<Json<Attestation>, (StatusCode, String)> {
    // Validate
    if req.name.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Name is required".into()));
    }
    if req.completions.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "No module completions provided".into(),
        ));
    }

    let issued_at = Utc::now().to_rfc3339();
    let att_id = generate_attestation_id(&req.name, &issued_at);
    let epoch = current_epoch();

    // Get previous attestation hash for chain linkage
    let db_path = format!("{}/attestations.db", state.0.data_dir);
    let conn = rusqlite::Connection::open(&db_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let prev_hash: Option<String> = conn
        .query_row(
            "SELECT attestation_hash FROM attestations ORDER BY created_at DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .ok();

    // Compute content hash
    let attestation_hash = compute_attestation_hash(
        &att_id,
        &req.name,
        &req.track,
        req.completions.len() as u32,
        &issued_at,
        &prev_hash,
    );

    // Sign with server's Ed25519 key
    let signature = {
        let sig = state
            .0
            .identity
            .signing_key
            .sign(attestation_hash.as_bytes());
        hex::encode(sig.to_bytes())
    };

    let signer_public_key = state.0.identity.public_key_hex.clone();

    let attestation = Attestation {
        id: att_id.clone(),
        name: req.name.clone(),
        track: req.track.clone(),
        modules_completed: req.completions.len() as u32,
        completions: req.completions.clone(),
        issued_at: issued_at.clone(),
        attestation_hash: attestation_hash.clone(),
        signature: signature.clone(),
        signer_public_key: signer_public_key.clone(),
        epoch,
        prev_attestation_hash: prev_hash.clone(),
    };

    // Persist
    let completions_json = serde_json::to_string(&req.completions)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    conn.execute(
        "INSERT INTO attestations (
            id, name, track, modules_completed, completions_json,
            issued_at, attestation_hash, signature, signer_public_key,
            epoch, prev_attestation_hash
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            att_id,
            req.name,
            req.track,
            req.completions.len() as u32,
            completions_json,
            issued_at,
            attestation_hash,
            signature,
            signer_public_key,
            epoch as i64,
            prev_hash,
        ],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::info!(
        attestation_id = %att_id,
        name = %req.name,
        track = %req.track,
        modules = %req.completions.len(),
        "Attestation issued"
    );

    Ok(Json(attestation))
}

/// GET /api/v1/attestations?id=ZP-ATT-2026-A3F2 — Look up an attestation.
pub async fn lookup_attestation_handler(
    State(state): State<AppState>,
    Query(query): Query<LookupQuery>,
) -> Result<Json<Attestation>, (StatusCode, String)> {
    let att_id = query
        .id
        .ok_or((StatusCode::BAD_REQUEST, "Missing 'id' parameter".into()))?;

    let db_path = format!("{}/attestations.db", state.0.data_dir);
    let conn = rusqlite::Connection::open(&db_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = conn
        .query_row(
            "SELECT id, name, track, modules_completed, completions_json,
                    issued_at, attestation_hash, signature, signer_public_key,
                    epoch, prev_attestation_hash
             FROM attestations WHERE id = ?1",
            params![att_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            },
        )
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                format!("Attestation {} not found", att_id),
            )
        })?;

    let completions: Vec<ModuleCompletion> = serde_json::from_str(&row.4).unwrap_or_default();

    Ok(Json(Attestation {
        id: row.0,
        name: row.1,
        track: row.2,
        modules_completed: row.3,
        completions,
        issued_at: row.5,
        attestation_hash: row.6,
        signature: row.7,
        signer_public_key: row.8,
        epoch: row.9 as u64,
        prev_attestation_hash: row.10,
    }))
}

/// GET /api/v1/attestations/all — List all attestations (summary only).
pub async fn list_attestations_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<AttestationSummary>>, (StatusCode, String)> {
    let db_path = format!("{}/attestations.db", state.0.data_dir);
    let conn = rusqlite::Connection::open(&db_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut stmt = conn
        .prepare(
            "SELECT id, name, track, modules_completed, issued_at, attestation_hash
             FROM attestations ORDER BY created_at DESC",
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows = stmt
        .query_map([], |row| {
            Ok(AttestationSummary {
                id: row.get(0)?,
                name: row.get(1)?,
                track: row.get(2)?,
                modules_completed: row.get(3)?,
                issued_at: row.get(4)?,
                attestation_hash: row.get(5)?,
                verified: true, // TODO: re-verify signature on read
            })
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let summaries: Vec<AttestationSummary> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(summaries))
}

// ============================================================================
// Anonymous Analytics Handlers
// ============================================================================

/// POST /api/v1/analytics/event — Record an anonymous course event.
///
/// No identity, no name, no IP logging. The session_id is a random token
/// the browser generates on first load — it groups events within a single
/// learning session but cannot identify a person.
pub async fn record_analytics_handler(
    State(state): State<AppState>,
    Json(event): Json<AnalyticsEvent>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Validate event type
    let valid_events = [
        "started",
        "completed",
        "checkpoint_started",
        "checkpoint_completed",
    ];
    if !valid_events.contains(&event.event.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Invalid event type: {}", event.event),
        ));
    }
    if event.module_id < 1 || event.module_id > 14 {
        return Err((StatusCode::BAD_REQUEST, "Module ID must be 1-14".into()));
    }

    let db_path = format!("{}/attestations.db", state.0.data_dir);
    let conn = rusqlite::Connection::open(&db_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    conn.execute(
        "INSERT INTO course_analytics (session_id, track, module_id, event, duration_secs)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            event.session_id,
            event.track,
            event.module_id,
            event.event,
            event.duration_secs,
        ],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/v1/analytics/course?track=track-2-builder — Aggregate course analytics.
///
/// Returns per-module starts, completions, completion rates, and median durations.
/// All data is aggregate — no individual sessions exposed.
pub async fn course_analytics_handler(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<CourseAnalytics>, (StatusCode, String)> {
    let track = params
        .get("track")
        .cloned()
        .unwrap_or_else(|| "track-2-builder".into());

    let db_path = format!("{}/attestations.db", state.0.data_dir);
    let conn = rusqlite::Connection::open(&db_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Total unique sessions for this track
    let total_sessions: u64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT session_id) FROM course_analytics WHERE track = ?1",
            params![track],
            |row| row.get(0),
        )
        .unwrap_or(0);

    // Sessions that completed all 14 modules
    let full_completions: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM (
                SELECT session_id FROM course_analytics
                WHERE track = ?1 AND event = 'completed'
                GROUP BY session_id
                HAVING COUNT(DISTINCT module_id) = 14
            )",
            params![track],
            |row| row.get(0),
        )
        .unwrap_or(0);

    // Per-module analytics
    let mut modules = Vec::new();
    for module_id in 1..=14u32 {
        let starts: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM course_analytics
                 WHERE track = ?1 AND module_id = ?2 AND event = 'started'",
                params![track, module_id],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let completions: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM course_analytics
                 WHERE track = ?1 AND module_id = ?2 AND event = 'completed'",
                params![track, module_id],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let checkpoint_starts: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM course_analytics
                 WHERE track = ?1 AND module_id = ?2 AND event = 'checkpoint_started'",
                params![track, module_id],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let checkpoint_completions: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM course_analytics
                 WHERE track = ?1 AND module_id = ?2 AND event = 'checkpoint_completed'",
                params![track, module_id],
                |row| row.get(0),
            )
            .unwrap_or(0);

        // Median duration (for completed events with duration)
        let median_duration: Option<u64> = {
            let stmt = conn
                .prepare(
                    "SELECT duration_secs FROM course_analytics
                     WHERE track = ?1 AND module_id = ?2 AND event = 'completed'
                     AND duration_secs IS NOT NULL
                     ORDER BY duration_secs",
                )
                .ok();

            stmt.and_then(|mut s| {
                let durations: Vec<u64> = s
                    .query_map(params![track, module_id], |row| row.get(0))
                    .ok()?
                    .filter_map(|r| r.ok())
                    .collect();

                if durations.is_empty() {
                    None
                } else {
                    Some(durations[durations.len() / 2])
                }
            })
        };

        let completion_rate = if starts > 0 {
            (completions as f64 / starts as f64 * 100.0).round() / 100.0
        } else {
            0.0
        };

        modules.push(ModuleAnalytics {
            module_id,
            starts,
            completions,
            completion_rate,
            median_duration_secs: median_duration,
            checkpoint_starts,
            checkpoint_completions,
        });
    }

    Ok(Json(CourseAnalytics {
        track,
        total_sessions,
        full_completions,
        modules,
    }))
}
