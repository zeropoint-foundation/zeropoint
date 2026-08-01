//! Phase 1 tool utilities per `docs/REGENT-PHASE-0-1-DESIGN-2026-07.md`.
//!
//! # Status: three pure-function tools shipped, two remain scaffold
//!
//! **Shipped as real implementations (2026-08-01):**
//! - `strip_html` — HTML → plain text via a small state machine.
//! - `generate_chart_html` — self-contained SVG chart (no external
//!   dependencies, no CDN, no JS; deterministic given input).
//! - `assemble_report_html` — dark-themed HTML report with inline SVG
//!   charts and sections.
//!
//! **Still scaffold (returns `Err(not_yet_implemented(...))`):**
//! - `save_to_artifacts` — file I/O + `artifact:library:candidate`
//!   receipt emission; depends on `ARTIFACT-LIBRARY-2026-05.md`
//!   supersession lifecycle. Ships next.
//!
//! # Design-doc deviation: SVG instead of Chart.js
//!
//! The design doc proposes Chart.js via a vendored copy with
//! `<iframe srcdoc="...">` embedding. Shipping SVG instead because:
//!   1. Zero external JS → no SRI/CDN policy question, no
//!      `no_external_script_without_integrity` interaction.
//!   2. Deterministic: identical inputs → byte-identical output, which
//!      matches `report_assemble`'s content-address-anchoring intent
//!      (see design doc §1.6: "content hash is on chain").
//!   3. Self-contained without iframes; simpler DOM.
//! The design doc allows this: §"tool comparison" lists chart_generate
//! as "Produces self-contained HTML/SVG chart from structured data."
//!
//! # Safety posture
//!
//! Delegation state (2026-08-01):
//!
//! - **`chart_generate` and `report_assemble` are wired.** They appear
//!   in `REGENT_TOOLS`, the gate honours them, and the dispatch arms
//!   in `regent.rs` call these utilities. Each dispatch emits a
//!   `regent:tool:artifact:<name>` receipt carrying the blake3 hash of
//!   the produced bytes, per the design doc §1.6 content-address-
//!   anchoring intent.
//! - **Not on `APPROVAL_REQUIRED_TOOLS`.** These are pure functions
//!   that return strings to Regent — no external I/O, no disk writes
//!   (see `save_to_artifacts` below). The approval-required precedent
//!   (`browser_use`) targets tools that "act outside the substrate";
//!   these do not. When `save_to_artifacts` lands and these tools
//!   begin writing to the operator's artifact library, revisit that
//!   decision.
//! - **`web_search`, `web_fetch`, `image_generate` remain unlisted.**
//!   Their dispatch arms in `regent.rs` return
//!   `not_yet_implemented(...)`. The arms are belt-and-suspenders
//!   "gate somehow bypassed" failure mode — the gate itself blocks
//!   invocation because these are not in `REGENT_TOOLS`.
//! - **`strip_html`** is a pure utility with no dispatch arm; it will
//!   be used inline by `web_fetch` when that tool ships.

use std::fmt::Write as _;
use std::path::PathBuf;

use zp_regent::error::RegentError;

/// Message prefix used by scaffold functions that still return `Err`.
/// The substrate-observability layer matches on this to distinguish
/// "tool not yet built" from "tool built but failed."
const NOT_YET_IMPLEMENTED_PREFIX: &str = "phase 1 tool scaffold: ";

fn scaffold_error(tool: &str) -> RegentError {
    RegentError::Execution(format!(
        "{prefix}{tool} not yet implemented — see \
         docs/REGENT-PHASE-0-1-DESIGN-2026-07.md and session handoff for \
         Tier B/C shipping plan.",
        prefix = NOT_YET_IMPLEMENTED_PREFIX,
        tool = tool,
    ))
}

/// Return the canonical "not implemented" sentinel error for a tool. The
/// dispatch arms in `regent.rs` use this to fail fast with a consistent
/// message that substrate-observability tools can pattern-match on.
pub fn not_yet_implemented(tool: &str) -> RegentError {
    scaffold_error(tool)
}

/// Chart spec for `chart_generate`. Kept minimal — enough for the
/// competitive-analysis example in the design doc (bar/line, one or
/// more numeric series against shared labels). Pie is supported for
/// single-series input.
#[derive(Debug, Clone)]
pub struct ChartSpec {
    /// One of `"line"`, `"bar"`, `"pie"`. Anything else falls back to
    /// `"bar"` with a warning in the generated SVG title.
    pub chart_type: String,
    pub title: Option<String>,
    pub labels: Vec<String>,
    pub series: Vec<ChartSeries>,
}

#[derive(Debug, Clone)]
pub struct ChartSeries {
    pub name: String,
    pub values: Vec<f64>,
}

/// Fragment of a report produced by Regent for `report_assemble` to fold
/// into a full HTML document. Fragments are ordered by the caller.
#[derive(Debug, Clone)]
pub struct ReportFragment {
    pub heading: Option<String>,
    /// Plain text or minimal HTML. Passed through with only `<script>`
    /// and `<style>` block tags stripped defensively (see
    /// `sanitize_fragment_html`); other structural tags survive so
    /// callers can supply headings, paragraphs, lists.
    pub body_html: String,
    /// Optional inline SVG chart string produced by
    /// `generate_chart_html`. Embedded directly into the report DOM
    /// (not iframe-boxed).
    pub chart_svg: Option<String>,
}

// ── Function implementations ────────────────────────────────────────────────

/// Extract plain text from an HTML document.
///
/// State machine handles:
///   - tags (elided entirely, incl. attribute values with `>` inside strings)
///   - HTML entities `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#NNN;`, `&#xHH;`
///   - `<script>` / `<style>` block content (elided in full)
///   - `<br>` / `</p>` / block-level tags collapsed to a single newline
///
/// Not a full HTML5 parser — designed for `web_fetch`'s "give Regent
/// readable text" job. Nested `<script>` or malformed input yields
/// best-effort output rather than an error.
pub fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let bytes = html.as_bytes();
    let mut i = 0;
    let n = bytes.len();
    // States: 0 = text, 1 = inside a tag, 2 = inside a <script>/<style> block
    let mut state: u8 = 0;
    let mut skip_until_tag: Option<&'static [u8]> = None;

    while i < n {
        match state {
            0 => {
                let b = bytes[i];
                if b == b'<' {
                    // Detect script/style block-start
                    let rest = &bytes[i + 1..];
                    if starts_with_ci(rest, b"script") {
                        skip_until_tag = Some(b"</script>");
                        state = 2;
                        i += 1;
                        continue;
                    }
                    if starts_with_ci(rest, b"style") {
                        skip_until_tag = Some(b"</style>");
                        state = 2;
                        i += 1;
                        continue;
                    }
                    // Insert a newline for block-level closers / <br>
                    if is_block_boundary_tag(rest) {
                        push_soft_newline(&mut out);
                    }
                    state = 1;
                    i += 1;
                } else if b == b'&' {
                    if let Some((decoded, consumed)) = decode_entity(&bytes[i..]) {
                        out.push_str(&decoded);
                        i += consumed;
                    } else {
                        out.push('&');
                        i += 1;
                    }
                } else {
                    // Normalize CR/LF/TAB to space; keep single \n intentional
                    let ch = b as char;
                    if ch == '\r' {
                        i += 1;
                        continue;
                    }
                    if ch == '\n' || ch == '\t' {
                        // Collapse runs of whitespace to a single space
                        if !out.ends_with(' ') && !out.ends_with('\n') {
                            out.push(' ');
                        }
                        i += 1;
                        continue;
                    }
                    if ch == ' ' && (out.ends_with(' ') || out.ends_with('\n')) {
                        i += 1;
                        continue;
                    }
                    out.push(ch);
                    i += 1;
                }
            }
            1 => {
                // Inside a tag — skip until matching '>', respecting quoted attr values
                let b = bytes[i];
                if b == b'"' || b == b'\'' {
                    let quote = b;
                    i += 1;
                    while i < n && bytes[i] != quote {
                        i += 1;
                    }
                    if i < n {
                        i += 1; // consume the closing quote
                    }
                    continue;
                }
                if b == b'>' {
                    state = 0;
                    i += 1;
                    continue;
                }
                i += 1;
            }
            2 => {
                // Inside <script>/<style> — skip to matching closer
                if let Some(closer) = skip_until_tag {
                    if let Some(pos) = find_ci(&bytes[i..], closer) {
                        i += pos + closer.len();
                        skip_until_tag = None;
                        state = 0;
                    } else {
                        // No closer found — consume rest
                        break;
                    }
                } else {
                    state = 0;
                }
            }
            _ => unreachable!(),
        }
    }

    // Final normalization: strip trailing whitespace, collapse triple+ newlines
    let mut result = String::with_capacity(out.len());
    let mut prev_nl = false;
    for ch in out.chars() {
        if ch == '\n' {
            if !prev_nl {
                result.push('\n');
                prev_nl = true;
            }
        } else {
            result.push(ch);
            prev_nl = false;
        }
    }
    result.trim().to_string()
}

fn starts_with_ci(hay: &[u8], needle: &[u8]) -> bool {
    if hay.len() < needle.len() {
        return false;
    }
    for i in 0..needle.len() {
        if hay[i].to_ascii_lowercase() != needle[i].to_ascii_lowercase() {
            return false;
        }
    }
    // Followed by a non-alphanumeric character (so `<scripts>` doesn't match `<script>`)
    if hay.len() > needle.len() {
        let next = hay[needle.len()];
        if next.is_ascii_alphanumeric() {
            return false;
        }
    }
    true
}

fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    'outer: for start in 0..=(hay.len() - needle.len()) {
        for j in 0..needle.len() {
            if hay[start + j].to_ascii_lowercase() != needle[j].to_ascii_lowercase() {
                continue 'outer;
            }
        }
        return Some(start);
    }
    None
}

/// Rest is the bytes AFTER the '<'. Returns true for closing tags of
/// block-level elements or self-closing `<br>`/`<hr>` variants — used
/// to insert a single soft newline between blocks.
fn is_block_boundary_tag(rest: &[u8]) -> bool {
    const BLOCKS: &[&[u8]] = &[
        b"/p", b"/div", b"/section", b"/article", b"/h1", b"/h2", b"/h3", b"/h4",
        b"/h5", b"/h6", b"/li", b"/tr", b"/ul", b"/ol", b"/pre", b"/blockquote",
        b"br", b"br/", b"br /", b"hr", b"hr/", b"hr /",
    ];
    for tag in BLOCKS {
        if starts_with_ci(rest, tag) {
            return true;
        }
    }
    false
}

fn push_soft_newline(out: &mut String) {
    if !out.ends_with('\n') {
        // Trim trailing spaces before the newline
        while out.ends_with(' ') {
            out.pop();
        }
        out.push('\n');
    }
}

fn decode_entity(bytes: &[u8]) -> Option<(String, usize)> {
    // bytes starts with '&'. Find the ';' within a reasonable window.
    let end = bytes.iter().take(10).position(|&b| b == b';')?;
    let inner = &bytes[1..end];
    let consumed = end + 1;
    let decoded = match inner {
        b"amp" => "&".to_string(),
        b"lt" => "<".to_string(),
        b"gt" => ">".to_string(),
        b"quot" => "\"".to_string(),
        b"apos" => "'".to_string(),
        b"nbsp" => " ".to_string(),
        _ => {
            if inner.first() == Some(&b'#') {
                let num_str = std::str::from_utf8(&inner[1..]).ok()?;
                let cp: u32 = if let Some(hex) = num_str.strip_prefix(&['x', 'X'][..]) {
                    u32::from_str_radix(hex, 16).ok()?
                } else {
                    num_str.parse().ok()?
                };
                char::from_u32(cp).map(|c| c.to_string())?
            } else {
                return None;
            }
        }
    };
    Some((decoded, consumed))
}

// ── Chart SVG generation ────────────────────────────────────────────────────

const CHART_WIDTH: f64 = 640.0;
const CHART_HEIGHT: f64 = 360.0;
const CHART_MARGIN_TOP: f64 = 40.0;
const CHART_MARGIN_BOTTOM: f64 = 60.0;
const CHART_MARGIN_LEFT: f64 = 60.0;
const CHART_MARGIN_RIGHT: f64 = 20.0;

// ZP palette (from REGENT-PHASE-0-1-DESIGN §1.6 dark theme).
const COLOR_BG: &str = "#0a0a0c";
const COLOR_FG: &str = "#e6e6e8";
const COLOR_MUTED: &str = "#7d7d85";
const SERIES_COLORS: &[&str] = &[
    "#7eb8da", "#dab87e", "#b87eda", "#7edab8", "#da7e8b", "#8bda7e",
];

/// Generate a self-contained SVG chart string. Deterministic: identical
/// input → byte-identical output. Suitable for content-address
/// anchoring per REGENT-PHASE-0-1-DESIGN §1.6.
///
/// Chart types:
///   - `"bar"` — vertical bars, series side-by-side, grouped by label
///   - `"line"` — lines with data points, one per series
///   - `"pie"` — first series only; slices per label, proportional to value
///
/// Unknown chart types fall back to `"bar"` with a `[warning]` prefix
/// on the title so the operator sees the fallback rather than silently
/// getting a different shape than requested.
pub fn generate_chart_html(spec: &ChartSpec) -> Result<String, RegentError> {
    if spec.series.is_empty() {
        return Err(RegentError::Execution(
            "chart spec has no series".to_string(),
        ));
    }
    if spec.labels.is_empty() && spec.chart_type != "pie" {
        return Err(RegentError::Execution(
            "chart spec has no labels".to_string(),
        ));
    }
    for series in &spec.series {
        if series.values.len() != spec.labels.len() && spec.chart_type != "pie" {
            return Err(RegentError::Execution(format!(
                "series '{}' has {} values but chart has {} labels",
                series.name,
                series.values.len(),
                spec.labels.len(),
            )));
        }
    }

    let (kind, title_prefix) = match spec.chart_type.as_str() {
        "bar" | "line" | "pie" => (spec.chart_type.as_str(), ""),
        _ => ("bar", "[warning: unknown chart type, falling back to bar] "),
    };

    let title = spec.title.as_deref().unwrap_or("");
    let title_text = format!("{}{}", title_prefix, title);

    let mut svg = String::new();
    // xmlns is required for standalone SVG rendering in a browser.
    let _ = write!(
        svg,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{}\" height=\"{}\" viewBox=\"0 0 {} {}\" role=\"img\" aria-label=\"{}\">",
        CHART_WIDTH,
        CHART_HEIGHT,
        CHART_WIDTH,
        CHART_HEIGHT,
        escape_xml(&title_text),
    );
    let _ = write!(
        svg,
        "<rect width=\"{}\" height=\"{}\" fill=\"{}\"/>",
        CHART_WIDTH, CHART_HEIGHT, COLOR_BG,
    );
    if !title_text.is_empty() {
        let _ = write!(
            svg,
            "<text x=\"{}\" y=\"22\" fill=\"{}\" font-family=\"Inter, system-ui, sans-serif\" font-size=\"14\" font-weight=\"600\">{}</text>",
            CHART_MARGIN_LEFT,
            COLOR_FG,
            escape_xml(&title_text),
        );
    }

    match kind {
        "bar" => write_bar_chart(&mut svg, spec),
        "line" => write_line_chart(&mut svg, spec),
        "pie" => write_pie_chart(&mut svg, spec),
        _ => unreachable!(),
    }

    svg.push_str("</svg>");
    Ok(svg)
}

fn plot_area() -> (f64, f64, f64, f64) {
    let x = CHART_MARGIN_LEFT;
    let y = CHART_MARGIN_TOP;
    let w = CHART_WIDTH - CHART_MARGIN_LEFT - CHART_MARGIN_RIGHT;
    let h = CHART_HEIGHT - CHART_MARGIN_TOP - CHART_MARGIN_BOTTOM;
    (x, y, w, h)
}

fn series_max(spec: &ChartSpec) -> f64 {
    let mut m = f64::MIN;
    for s in &spec.series {
        for v in &s.values {
            if *v > m {
                m = *v;
            }
        }
    }
    if m <= 0.0 {
        1.0
    } else {
        m * 1.1 // headroom so bars don't kiss the top
    }
}

fn write_bar_chart(svg: &mut String, spec: &ChartSpec) {
    let (px, py, pw, ph) = plot_area();
    let max_val = series_max(spec);
    let n_labels = spec.labels.len() as f64;
    let n_series = spec.series.len() as f64;
    let group_width = pw / n_labels;
    let bar_width = (group_width * 0.7) / n_series;
    let group_padding = (group_width - bar_width * n_series) / 2.0;

    // Axis lines
    let _ = write!(
        svg,
        "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"{}\" stroke-width=\"1\"/>",
        px, py + ph, px + pw, py + ph, COLOR_MUTED,
    );
    let _ = write!(
        svg,
        "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"{}\" stroke-width=\"1\"/>",
        px, py, px, py + ph, COLOR_MUTED,
    );

    // Bars
    for (li, label) in spec.labels.iter().enumerate() {
        let group_x = px + (li as f64) * group_width + group_padding;
        for (si, series) in spec.series.iter().enumerate() {
            let v = series.values[li];
            let bh = (v / max_val) * ph;
            let bx = group_x + (si as f64) * bar_width;
            let by = py + ph - bh;
            let color = SERIES_COLORS[si % SERIES_COLORS.len()];
            let _ = write!(
                svg,
                "<rect x=\"{:.2}\" y=\"{:.2}\" width=\"{:.2}\" height=\"{:.2}\" fill=\"{}\"/>",
                bx, by, bar_width, bh, color,
            );
        }
        // Label
        let label_x = px + (li as f64) * group_width + group_width / 2.0;
        let _ = write!(
            svg,
            "<text x=\"{:.2}\" y=\"{:.2}\" fill=\"{}\" font-family=\"Inter, system-ui, sans-serif\" font-size=\"11\" text-anchor=\"middle\">{}</text>",
            label_x, py + ph + 16.0, COLOR_MUTED, escape_xml(label),
        );
    }

    write_legend(svg, spec);
}

fn write_line_chart(svg: &mut String, spec: &ChartSpec) {
    let (px, py, pw, ph) = plot_area();
    let max_val = series_max(spec);
    let n_labels = spec.labels.len();
    if n_labels < 2 {
        return;
    }
    let x_step = pw / ((n_labels - 1) as f64);

    // Axis lines
    let _ = write!(
        svg,
        "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"{}\" stroke-width=\"1\"/>",
        px, py + ph, px + pw, py + ph, COLOR_MUTED,
    );
    let _ = write!(
        svg,
        "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"{}\" stroke-width=\"1\"/>",
        px, py, px, py + ph, COLOR_MUTED,
    );

    for (si, series) in spec.series.iter().enumerate() {
        let color = SERIES_COLORS[si % SERIES_COLORS.len()];
        let mut d = String::new();
        for (i, v) in series.values.iter().enumerate() {
            let x = px + (i as f64) * x_step;
            let y = py + ph - (v / max_val) * ph;
            if i == 0 {
                let _ = write!(d, "M{:.2},{:.2}", x, y);
            } else {
                let _ = write!(d, " L{:.2},{:.2}", x, y);
            }
        }
        let _ = write!(
            svg,
            "<path d=\"{}\" fill=\"none\" stroke=\"{}\" stroke-width=\"2\"/>",
            d, color,
        );
        for (i, v) in series.values.iter().enumerate() {
            let x = px + (i as f64) * x_step;
            let y = py + ph - (v / max_val) * ph;
            let _ = write!(
                svg,
                "<circle cx=\"{:.2}\" cy=\"{:.2}\" r=\"3\" fill=\"{}\"/>",
                x, y, color,
            );
        }
    }

    // X-axis labels
    for (i, label) in spec.labels.iter().enumerate() {
        let x = px + (i as f64) * x_step;
        let _ = write!(
            svg,
            "<text x=\"{:.2}\" y=\"{:.2}\" fill=\"{}\" font-family=\"Inter, system-ui, sans-serif\" font-size=\"11\" text-anchor=\"middle\">{}</text>",
            x, py + ph + 16.0, COLOR_MUTED, escape_xml(label),
        );
    }

    write_legend(svg, spec);
}

fn write_pie_chart(svg: &mut String, spec: &ChartSpec) {
    // Only the first series is used for pie. Slices correspond to values;
    // labels are optional (fall back to "series 0 / 1 / 2 ..." if empty).
    let series = &spec.series[0];
    let total: f64 = series.values.iter().sum();
    if total <= 0.0 {
        return;
    }
    let cx = CHART_WIDTH / 2.0;
    let cy = (CHART_MARGIN_TOP + CHART_HEIGHT - CHART_MARGIN_BOTTOM) / 2.0;
    let r = ((CHART_HEIGHT - CHART_MARGIN_TOP - CHART_MARGIN_BOTTOM) / 2.0) - 10.0;
    let mut start_angle = -std::f64::consts::FRAC_PI_2; // start at 12 o'clock
    for (i, v) in series.values.iter().enumerate() {
        let sweep = (v / total) * std::f64::consts::TAU;
        let end_angle = start_angle + sweep;
        let x1 = cx + r * start_angle.cos();
        let y1 = cy + r * start_angle.sin();
        let x2 = cx + r * end_angle.cos();
        let y2 = cy + r * end_angle.sin();
        let large_arc = if sweep > std::f64::consts::PI { 1 } else { 0 };
        let color = SERIES_COLORS[i % SERIES_COLORS.len()];
        let _ = write!(
            svg,
            "<path d=\"M{:.2},{:.2} L{:.2},{:.2} A{:.2},{:.2} 0 {} 1 {:.2},{:.2} Z\" fill=\"{}\"/>",
            cx, cy, x1, y1, r, r, large_arc, x2, y2, color,
        );
        start_angle = end_angle;
    }

    // Legend uses labels if present, else "series 0/1/..."
    let legend_labels: Vec<String> = if spec.labels.len() == series.values.len() {
        spec.labels.clone()
    } else {
        (0..series.values.len()).map(|i| format!("slice {}", i)).collect()
    };
    write_pie_legend(svg, &legend_labels);
}

fn write_legend(svg: &mut String, spec: &ChartSpec) {
    let mut x = CHART_MARGIN_LEFT;
    let y = CHART_HEIGHT - 20.0;
    for (si, series) in spec.series.iter().enumerate() {
        let color = SERIES_COLORS[si % SERIES_COLORS.len()];
        let _ = write!(
            svg,
            "<rect x=\"{:.2}\" y=\"{:.2}\" width=\"10\" height=\"10\" fill=\"{}\"/>",
            x, y - 8.0, color,
        );
        let _ = write!(
            svg,
            "<text x=\"{:.2}\" y=\"{:.2}\" fill=\"{}\" font-family=\"Inter, system-ui, sans-serif\" font-size=\"11\">{}</text>",
            x + 14.0, y, COLOR_FG, escape_xml(&series.name),
        );
        x += 14.0 + (series.name.len() as f64) * 6.5 + 12.0;
    }
}

fn write_pie_legend(svg: &mut String, labels: &[String]) {
    let mut x = CHART_MARGIN_LEFT;
    let y = CHART_HEIGHT - 20.0;
    for (i, label) in labels.iter().enumerate() {
        let color = SERIES_COLORS[i % SERIES_COLORS.len()];
        let _ = write!(
            svg,
            "<rect x=\"{:.2}\" y=\"{:.2}\" width=\"10\" height=\"10\" fill=\"{}\"/>",
            x, y - 8.0, color,
        );
        let _ = write!(
            svg,
            "<text x=\"{:.2}\" y=\"{:.2}\" fill=\"{}\" font-family=\"Inter, system-ui, sans-serif\" font-size=\"11\">{}</text>",
            x + 14.0, y, COLOR_FG, escape_xml(label),
        );
        x += 14.0 + (label.len() as f64) * 6.5 + 12.0;
    }
}

fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

// ── Report assembly ─────────────────────────────────────────────────────────

/// Compose a full HTML report from fragments. Self-contained: embeds
/// styles inline, embeds any provided chart SVG inline (not iframe),
/// and passes body_html through a minimal sanitizer that strips
/// `<script>` and `<style>` blocks defensively but preserves ordinary
/// structural tags.
///
/// The output is deterministic given identical inputs. The design doc
/// §1.6 anchors the content hash of this output on chain via the
/// `report_assemble` completion receipt.
pub fn assemble_report_html(fragments: &[ReportFragment]) -> Result<String, RegentError> {
    if fragments.is_empty() {
        return Err(RegentError::Execution(
            "report has no fragments".to_string(),
        ));
    }

    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n");
    html.push_str("<meta name=\"generator\" content=\"ZeroPoint Regent report_assemble v1\">\n");
    html.push_str("<title>ZeroPoint Regent Report</title>\n");
    html.push_str("<style>\n");
    html.push_str(REPORT_STYLES);
    html.push_str("\n</style>\n</head>\n<body>\n");
    html.push_str("<main class=\"report\">\n");

    for frag in fragments {
        html.push_str("<section class=\"fragment\">\n");
        if let Some(heading) = &frag.heading {
            let _ = write!(html, "<h2>{}</h2>\n", escape_xml(heading));
        }
        let sanitized = sanitize_fragment_html(&frag.body_html);
        html.push_str(&sanitized);
        html.push('\n');
        if let Some(svg) = &frag.chart_svg {
            html.push_str("<figure class=\"chart\">\n");
            html.push_str(svg);
            html.push_str("\n</figure>\n");
        }
        html.push_str("</section>\n");
    }

    html.push_str("<footer class=\"footer\">\n");
    html.push_str("Generated by ZeroPoint Regent · chain-anchored via <code>report_assemble</code>\n");
    html.push_str("</footer>\n</main>\n</body>\n</html>\n");
    Ok(html)
}

/// Strip `<script>` and `<style>` blocks and their content from a
/// fragment. Not a full sanitizer — the trust boundary here is
/// "content Regent authored," not arbitrary user HTML — but scripts
/// have no legitimate use in a static report and would break the
/// deterministic-hash property.
fn sanitize_fragment_html(html: &str) -> String {
    strip_block(&strip_block(html, "script"), "style")
}

fn strip_block(html: &str, tag: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut i = 0;
    let bytes = html.as_bytes();
    let open = format!("<{}", tag).into_bytes();
    let close = format!("</{}>", tag).into_bytes();
    while i < bytes.len() {
        if starts_with_ci(&bytes[i..], &open) {
            // Skip until the matching close, or end-of-input
            if let Some(end) = find_ci(&bytes[i..], &close) {
                i += end + close.len();
            } else {
                break;
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

const REPORT_STYLES: &str = "\
:root { --bg: #0a0a0c; --fg: #e6e6e8; --muted: #7d7d85; --accent: #7eb8da; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font-family: Inter, system-ui, sans-serif; line-height: 1.55; }
.report { max-width: 780px; margin: 0 auto; padding: 48px 24px; }
h1, h2, h3 { color: var(--fg); font-weight: 600; letter-spacing: -0.01em; }
h2 { margin-top: 40px; padding-bottom: 8px; border-bottom: 1px solid #1c1c22; }
p { margin: 12px 0; }
code, pre { font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 0.92em; color: var(--accent); }
.fragment { margin-bottom: 32px; }
.chart { margin: 24px 0; text-align: center; }
.chart svg { max-width: 100%; height: auto; }
.footer { margin-top: 64px; padding-top: 16px; border-top: 1px solid #1c1c22; color: var(--muted); font-size: 0.88em; }
";

// ── Still-scaffold: save_to_artifacts ───────────────────────────────────────

/// Persist a completed artifact under the operator's artifact library
/// and return the on-disk path.
///
/// **Scaffold** — returns `Err`. Real implementation will:
/// 1. Compute the artifact's content hash (blake3).
/// 2. Write to `~/.zeropoint/artifacts/<hash>.<ext>` (or the operator's
///    configured artifact directory).
/// 3. Emit an `artifact:library:candidate` receipt via the audit store
///    per `docs/design/ARTIFACT-LIBRARY-2026-05.md` supersession
///    lifecycle.
///
/// Deferred because the audit-store integration requires either
/// threading `&Arc<Mutex<AuditStore>>` through this function (breaking
/// the pure-utility discipline of this module) or introducing a
/// callback surface. That decision is small but wants to be made
/// explicitly rather than during a tool-shipping sprint.
pub fn save_to_artifacts(
    _name: &str,
    _content: &[u8],
) -> Result<PathBuf, RegentError> {
    Err(scaffold_error("save_to_artifacts"))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── strip_html ─────────────────────────────────────────────────────

    #[test]
    fn strip_html_removes_tags() {
        assert_eq!(strip_html("<p>hello world</p>"), "hello world");
    }

    #[test]
    fn strip_html_decodes_common_entities() {
        assert_eq!(
            strip_html("<p>Tom &amp; Jerry &lt;3 &quot;quoted&quot;</p>"),
            "Tom & Jerry <3 \"quoted\""
        );
    }

    #[test]
    fn strip_html_decodes_numeric_entities() {
        assert_eq!(strip_html("<p>&#8212; em dash</p>"), "\u{2014} em dash");
        assert_eq!(strip_html("<p>&#x27;apos&#x27;</p>"), "'apos'");
    }

    #[test]
    fn strip_html_elides_script_blocks() {
        let html = "<p>keep</p><script>alert('bad')</script><p>this</p>";
        assert!(strip_html(html).contains("keep"));
        assert!(strip_html(html).contains("this"));
        assert!(!strip_html(html).contains("alert"));
        assert!(!strip_html(html).contains("bad"));
    }

    #[test]
    fn strip_html_elides_style_blocks() {
        let html = "<style>body { color: red; }</style><p>visible</p>";
        assert_eq!(strip_html(html), "visible");
    }

    #[test]
    fn strip_html_handles_attribute_greater_than_in_quoted_string() {
        // Tag ends AT the first unquoted '>', not inside quoted attr values
        let html = r#"<a href="foo?a=1&b=2" title="x>y">link</a>"#;
        // The '>' inside the quoted attr must not be treated as tag-end.
        // Because our decoder is state-based, if it correctly stays inside
        // the quote until the matching quote, the text "link" is preserved
        // and no garbage leaks from the attribute.
        assert!(strip_html(html).contains("link"));
        assert!(!strip_html(html).contains("foo?a"));
        assert!(!strip_html(html).contains("title"));
    }

    #[test]
    fn strip_html_inserts_newline_at_block_boundaries() {
        let html = "<p>first</p><p>second</p>";
        assert_eq!(strip_html(html), "first\nsecond");
    }

    #[test]
    fn strip_html_collapses_whitespace() {
        let html = "  hello   \n\n  world  ";
        assert_eq!(strip_html(html), "hello world");
    }

    #[test]
    fn strip_html_empty_input() {
        assert_eq!(strip_html(""), "");
    }

    #[test]
    fn strip_html_unclosed_script_is_bounded() {
        // Malformed input: opening script never closed
        let html = "<p>keep</p><script>alert('bad')";
        let out = strip_html(html);
        assert!(out.contains("keep"));
        assert!(!out.contains("alert"));
    }

    // ── generate_chart_html ────────────────────────────────────────────

    fn bar_spec() -> ChartSpec {
        ChartSpec {
            chart_type: "bar".to_string(),
            title: Some("Q3 Revenue".to_string()),
            labels: vec!["A".to_string(), "B".to_string(), "C".to_string()],
            series: vec![ChartSeries {
                name: "USD (M)".to_string(),
                values: vec![10.0, 20.0, 15.0],
            }],
        }
    }

    #[test]
    fn chart_bar_produces_svg_with_expected_bones() {
        let svg = generate_chart_html(&bar_spec()).unwrap();
        assert!(svg.starts_with("<svg"));
        assert!(svg.ends_with("</svg>"));
        assert!(svg.contains("Q3 Revenue"));
        assert!(svg.contains("USD (M)")); // legend
        assert!(svg.contains("<rect")); // bars
    }

    #[test]
    fn chart_line_produces_svg_with_path() {
        let mut spec = bar_spec();
        spec.chart_type = "line".to_string();
        let svg = generate_chart_html(&spec).unwrap();
        assert!(svg.contains("<path")); // line
        assert!(svg.contains("<circle")); // data points
    }

    #[test]
    fn chart_pie_produces_svg_with_arcs() {
        let spec = ChartSpec {
            chart_type: "pie".to_string(),
            title: Some("Share".to_string()),
            labels: vec!["A".to_string(), "B".to_string(), "C".to_string()],
            series: vec![ChartSeries {
                name: "share".to_string(),
                values: vec![50.0, 30.0, 20.0],
            }],
        };
        let svg = generate_chart_html(&spec).unwrap();
        assert!(svg.contains("<path")); // arc slices
        assert!(svg.contains(" A"));    // arc command in path
    }

    #[test]
    fn chart_unknown_type_falls_back_to_bar_with_warning() {
        let mut spec = bar_spec();
        spec.chart_type = "sunburst".to_string();
        let svg = generate_chart_html(&spec).unwrap();
        assert!(svg.contains("warning"));
        assert!(svg.contains("<rect")); // still produces bars
    }

    #[test]
    fn chart_empty_series_errors() {
        let spec = ChartSpec {
            chart_type: "bar".to_string(),
            title: None,
            labels: vec!["A".to_string()],
            series: vec![],
        };
        assert!(generate_chart_html(&spec).is_err());
    }

    #[test]
    fn chart_series_length_mismatch_errors() {
        let spec = ChartSpec {
            chart_type: "bar".to_string(),
            title: None,
            labels: vec!["A".to_string(), "B".to_string()],
            series: vec![ChartSeries {
                name: "s".to_string(),
                values: vec![1.0], // only 1 value, 2 labels
            }],
        };
        assert!(generate_chart_html(&spec).is_err());
    }

    #[test]
    fn chart_output_is_deterministic() {
        let a = generate_chart_html(&bar_spec()).unwrap();
        let b = generate_chart_html(&bar_spec()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn chart_title_is_xml_escaped() {
        let mut spec = bar_spec();
        spec.title = Some("A & B <C>".to_string());
        let svg = generate_chart_html(&spec).unwrap();
        assert!(svg.contains("A &amp; B &lt;C&gt;"));
        assert!(!svg.contains("A & B <C>"));
    }

    // ── assemble_report_html ───────────────────────────────────────────

    #[test]
    fn report_produces_full_html_document() {
        let frags = vec![ReportFragment {
            heading: Some("Findings".to_string()),
            body_html: "<p>The quick brown fox.</p>".to_string(),
            chart_svg: None,
        }];
        let html = assemble_report_html(&frags).unwrap();
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("<title>ZeroPoint Regent Report</title>"));
        assert!(html.contains("<h2>Findings</h2>"));
        assert!(html.contains("The quick brown fox."));
        assert!(html.ends_with("</html>\n"));
    }

    #[test]
    fn report_embeds_chart_svg_inline() {
        let frags = vec![ReportFragment {
            heading: None,
            body_html: "<p>context</p>".to_string(),
            chart_svg: Some("<svg><rect/></svg>".to_string()),
        }];
        let html = assemble_report_html(&frags).unwrap();
        assert!(html.contains("<figure class=\"chart\">"));
        assert!(html.contains("<svg><rect/></svg>"));
        assert!(!html.contains("<iframe"));
    }

    #[test]
    fn report_strips_scripts_from_fragments() {
        let frags = vec![ReportFragment {
            heading: None,
            body_html: "<p>safe</p><script>alert(1)</script><p>also safe</p>".to_string(),
            chart_svg: None,
        }];
        let html = assemble_report_html(&frags).unwrap();
        assert!(html.contains("safe"));
        assert!(!html.contains("alert"));
        assert!(!html.contains("<script"));
    }

    #[test]
    fn report_strips_style_from_fragments() {
        let frags = vec![ReportFragment {
            heading: None,
            body_html: "<style>body { color: red }</style><p>text</p>".to_string(),
            chart_svg: None,
        }];
        let html = assemble_report_html(&frags).unwrap();
        // The report's own <style> block is in <head>, not from fragment;
        // fragment styles must be stripped, so no 'color: red' inside body
        assert!(!html.contains("color: red"));
    }

    #[test]
    fn report_heading_is_xml_escaped() {
        let frags = vec![ReportFragment {
            heading: Some("A & B".to_string()),
            body_html: "body".to_string(),
            chart_svg: None,
        }];
        let html = assemble_report_html(&frags).unwrap();
        assert!(html.contains("<h2>A &amp; B</h2>"));
    }

    #[test]
    fn report_empty_fragments_errors() {
        assert!(assemble_report_html(&[]).is_err());
    }

    #[test]
    fn report_output_is_deterministic() {
        let frags = vec![ReportFragment {
            heading: Some("H".to_string()),
            body_html: "b".to_string(),
            chart_svg: Some("<svg/>".to_string()),
        }];
        let a = assemble_report_html(&frags).unwrap();
        let b = assemble_report_html(&frags).unwrap();
        assert_eq!(a, b);
    }

    // ── still-scaffold ─────────────────────────────────────────────────

    #[test]
    fn save_to_artifacts_still_scaffold() {
        let err = save_to_artifacts("test.html", b"content").unwrap_err();
        assert!(err.to_string().contains(NOT_YET_IMPLEMENTED_PREFIX));
    }

    #[test]
    fn not_yet_implemented_names_the_tool() {
        let err = not_yet_implemented("web_search");
        assert!(err.to_string().contains("web_search"));
        assert!(err.to_string().contains(NOT_YET_IMPLEMENTED_PREFIX));
    }
}
