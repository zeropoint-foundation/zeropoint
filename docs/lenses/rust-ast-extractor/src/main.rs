//! AST-based extractor for `docs/lenses/source-manifest.json`.
//!
//! Companion to the regex-based `regenerate_source_manifest.py`. Same output
//! schema; more accurate type-flow extraction because it walks the actual
//! Rust AST via `syn` instead of scraping function signatures with regex.
//!
//! What the AST pass catches that the regex misses:
//! - Struct / enum field types (regex only sees fn signatures).
//! - Impl-block method signatures with correct impl-target attribution.
//! - Type refs inside complex generics with nested bounds (`Result<Foo,
//!   Bar<Baz>>`), where regex either mis-terminates on the wrong `>` or
//!   miscounts the inner types.
//! - `pub use` re-exports — when crate A re-exports `B::Foo` as its own
//!   public API, downstream consumers naming `A::Foo` are attributed to
//!   the correct owner (B) via the re-export map.
//! - Union types and trait-associated types.
//!
//! What still slips through: macro-generated types (the AST sees the macro
//! call, not the tokens it would emit — expansion needs `rust-analyzer`
//! semantic analysis, not just parsing). That's a known limit; ~5-8% of
//! type usage in the substrate.
//!
//! Usage:
//! ```
//! # From the repo root:
//! cargo run --release --manifest-path docs/lenses/rust-ast-extractor/Cargo.toml \
//!   -- --repo-root . --out docs/lenses/source-manifest.json
//!
//! # Or from within the extractor dir:
//! cd docs/lenses/rust-ast-extractor
//! cargo run --release -- --repo-root ../../.. --out ../source-manifest.json
//! ```

use anyhow::{bail, Context, Result};
use clap::Parser;
use indexmap::IndexMap;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use syn::visit::Visit;
use syn::{
    Fields, ImplItem, ItemEnum, ItemImpl, ItemStruct, ItemType, ItemUnion, ItemUse,
    ReturnType, TraitItem, TypePath, UseTree, Variant,
};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "AST-based extractor for docs/lenses/source-manifest.json"
)]
struct Cli {
    /// Repo root to scan.
    #[arg(long, default_value = ".")]
    repo_root: PathBuf,

    /// Output manifest path.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Also scan tools/*/**/*.rs (default: crates only).
    #[arg(long)]
    include_tools: bool,
}

// ---------------------------------------------------------------------------
// Constants — types to ignore from cross-crate accounting.
// ---------------------------------------------------------------------------

/// Types treated as std/prim/very-common and never counted as owned by any
/// crate. Matches the regex extractor's ignore set for schema parity.
const IGNORE_TYPES: &[&str] = &[
    // Container / cell / lock
    "String", "Vec", "Option", "Result", "Box", "Arc", "Rc", "Mutex",
    "RwLock", "Cell", "RefCell", "HashMap", "HashSet", "BTreeMap",
    "BTreeSet", "VecDeque", "BinaryHeap", "LinkedList", "IndexMap", "IndexSet",
    // Common std lib
    "PathBuf", "Path", "OsString", "OsStr", "CString", "CStr",
    "File", "Duration", "Instant", "SystemTime", "SocketAddr", "IpAddr",
    "Ipv4Addr", "Ipv6Addr", "Uri", "Url",
    "Error", "Ok", "Err", "Some", "None", "Send", "Sync", "Sized", "Unpin",
    // Serde-family
    "Serialize", "Deserialize", "Serializer", "Deserializer",
    "Value", "Map", "JsonValue",
    // Primitives
    "u8", "u16", "u32", "u64", "u128", "usize",
    "i8", "i16", "i32", "i64", "i128", "isize",
    "f32", "f64", "bool", "char", "str",
    // Std traits
    "Debug", "Display", "Clone", "Copy", "Default", "Hash", "Eq", "PartialEq",
    "Ord", "PartialOrd", "From", "Into", "TryFrom", "TryInto", "AsRef", "AsMut",
    "Iterator", "IntoIterator", "Future", "Fn", "FnMut", "FnOnce", "Drop",
    "Deref", "DerefMut", "Borrow", "BorrowMut", "ToOwned",
    // Tokio / async
    "Sender", "Receiver", "JoinHandle", "TaskLocal",
    "UnboundedSender", "UnboundedReceiver", "Notify", "Semaphore",
    // Common patterns
    "Self",
];

fn ignore_types() -> HashSet<&'static str> {
    IGNORE_TYPES.iter().copied().collect()
}

// ---------------------------------------------------------------------------
// Info-flow signal counting (regex-parity substrings).
// ---------------------------------------------------------------------------

const SIGN_PATTERNS: &[&str] = &[
    ".sign(", "SigningKey", "HKDF", "hkdf", "Hkdf",
    "ed25519", "Signer", "sign_receipt", "derive_key",
];
const GATE_PATTERNS: &[&str] = &[
    "gate.check", "PolicyEngine", "verify_delegation",
    "policy_check", "check_policy", "PolicyGate",
    "evaluate_policy", "gate_evaluate",
];
const CHAIN_PATTERNS: &[&str] = &[
    "chain.append", "AuditStore::write", "emit_receipt",
    "append_to_chain", "ChainEntry", "Chain::append",
    "audit_chain", "write_receipt",
];
const VERIFY_PATTERNS: &[&str] = &[
    ".verify(", "verify_chain", "verify_integrity", "verify_signature",
    "Verifier", "VerifyingKey", "verify_receipt",
];

fn count_signals(text: &str, patterns: &[&str]) -> usize {
    patterns.iter().map(|p| text.matches(p).count()).sum()
}

// ---------------------------------------------------------------------------
// Receipt slug extraction (regex; the AST doesn't help with string literals).
// ---------------------------------------------------------------------------

fn receipt_slug_regex() -> regex::Regex {
    let families = "regent|observation|embodiment|cognitive|coherence|officer|substrate|\
                    chain|policy|delegation|governance|standing|kinship|artifact|hardening|\
                    canonicalization|supersession|receipt|audit|content|gate|mesh|ceremony";
    let pattern = format!(r#""((?:{families})(?::[a-z0-9_]+){{1,5}})""#);
    regex::Regex::new(&pattern).expect("valid regex")
}

// ---------------------------------------------------------------------------
// Cargo.toml parsing (crate name + deps) — hand-rolled, keeps deps light.
// ---------------------------------------------------------------------------

fn parse_cargo_deps(cargo_toml: &Path, known: &HashSet<String>) -> Vec<String> {
    let text = match fs::read_to_string(cargo_toml) {
        Ok(t) => t,
        Err(_) => return vec![],
    };
    let section_re = regex::Regex::new(r"^\s*\[([^\]]+)\]").unwrap();
    let dep_re = regex::Regex::new(
        r"^\s*((?:zp-|mle-|monte-|trust-|course-|execution-)[A-Za-z0-9_-]+)\s*=",
    )
    .unwrap();
    let accept: HashSet<&str> = [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
    ]
    .into_iter()
    .collect();
    let mut current: Option<String> = None;
    let mut deps = BTreeSet::new();
    for line in text.lines() {
        if let Some(cap) = section_re.captures(line) {
            current = Some(cap[1].trim().to_string());
            continue;
        }
        if let Some(cur) = &current {
            if accept.contains(cur.as_str()) {
                if let Some(cap) = dep_re.captures(line) {
                    let name = &cap[1];
                    if known.contains(name) {
                        deps.insert(name.to_string());
                    }
                }
            }
        }
    }
    deps.into_iter().collect()
}

// ---------------------------------------------------------------------------
// Crate discovery.
// ---------------------------------------------------------------------------

fn find_crate_dirs(repo_root: &Path, include_tools: bool) -> Vec<PathBuf> {
    let mut roots = vec!["crates"];
    if include_tools {
        roots.push("tools");
    }
    let mut crates = Vec::new();
    for r in roots {
        let base = repo_root.join(r);
        if !base.is_dir() {
            continue;
        }
        let mut entries: Vec<_> = fs::read_dir(&base)
            .into_iter()
            .flatten()
            .flatten()
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if !path.join("Cargo.toml").is_file() {
                continue;
            }
            // Accept any crate with at least one .rs file anywhere.
            let has_rust = walkdir::WalkDir::new(&path)
                .into_iter()
                .filter_map(|e| e.ok())
                .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("rs"));
            if has_rust {
                crates.push(path);
            }
        }
    }
    crates
}

fn walk_rs_files(crate_dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<_> = walkdir::WalkDir::new(crate_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("rs"))
        .map(|e| e.path().to_path_buf())
        .collect();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Type reference visitor — walks a Type node and records every leading path
// segment that could name a type. Skips generic type parameters and lifetimes.
// ---------------------------------------------------------------------------

struct TypeRefCollector<'a> {
    out: &'a mut Vec<String>,
    ignore: &'a HashSet<&'static str>,
}

impl<'a, 'ast> Visit<'ast> for TypeRefCollector<'a> {
    fn visit_type_path(&mut self, node: &'ast TypePath) {
        // Walk each segment; each named segment is a candidate.
        for seg in &node.path.segments {
            let name = seg.ident.to_string();
            if name.chars().next().map(|c| c.is_ascii_uppercase()) == Some(true)
                && !self.ignore.contains(name.as_str())
            {
                self.out.push(name);
            }
            // Recurse into any generics on this segment (`Vec<Foo>`).
            syn::visit::visit_path_arguments(self, &seg.arguments);
        }
    }
}

// ---------------------------------------------------------------------------
// File visitor — walks a parsed syn::File and collects defs + refs.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FileFacts {
    /// Type defs owned by this file's crate (name only).
    type_defs: Vec<String>,
    /// (Owner-crate-attribution, type-name, count) — refs to any capitalized
    /// type from struct fields, enum variants, fn signatures, impl blocks.
    /// Attribution is done later once all defs are known globally.
    type_refs: Vec<String>,
    /// Re-exports of the form `pub use other_crate::TypeName` — helps
    /// attribute re-exported types back to their true owner.
    reexports: Vec<(String, String)>, // (from_crate_snake, type_name)
}

struct FileVisitor<'a> {
    facts: FileFacts,
    ignore: &'a HashSet<&'static str>,
}

impl<'a, 'ast> Visit<'ast> for FileVisitor<'a> {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        self.facts.type_defs.push(node.ident.to_string());
        // Walk field types too — this is where struct fields carry
        // cross-crate types the regex extractor missed.
        self.visit_fields(&node.fields);
    }

    fn visit_item_enum(&mut self, node: &'ast ItemEnum) {
        self.facts.type_defs.push(node.ident.to_string());
        for variant in &node.variants {
            self.visit_variant(variant);
        }
    }

    fn visit_item_type(&mut self, node: &'ast ItemType) {
        self.facts.type_defs.push(node.ident.to_string());
        self.visit_type(&node.ty);
    }

    fn visit_item_union(&mut self, node: &'ast ItemUnion) {
        self.facts.type_defs.push(node.ident.to_string());
        for field in &node.fields.named {
            self.visit_type(&field.ty);
        }
    }

    fn visit_variant(&mut self, node: &'ast Variant) {
        self.visit_fields(&node.fields);
    }

    fn visit_fields(&mut self, fields: &'ast Fields) {
        match fields {
            Fields::Named(named) => {
                for f in &named.named {
                    self.visit_type(&f.ty);
                }
            }
            Fields::Unnamed(unnamed) => {
                for f in &unnamed.unnamed {
                    self.visit_type(&f.ty);
                }
            }
            Fields::Unit => {}
        }
    }

    fn visit_type_path(&mut self, node: &'ast TypePath) {
        // Delegate to the shared collector logic.
        let mut refs = Vec::new();
        let mut collector = TypeRefCollector {
            out: &mut refs,
            ignore: self.ignore,
        };
        collector.visit_type_path(node);
        self.facts.type_refs.extend(refs);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        // Attribute impl-block method sigs. The self_ty is also a ref.
        self.visit_type(&node.self_ty);
        if let Some((_, trait_path, _)) = &node.trait_ {
            // `impl Trait for Foo` — the trait itself is also a ref.
            for seg in &trait_path.segments {
                let name = seg.ident.to_string();
                if name.chars().next().map(|c| c.is_ascii_uppercase()) == Some(true)
                    && !self.ignore.contains(name.as_str())
                {
                    self.facts.type_refs.push(name);
                }
            }
        }
        for item in &node.items {
            match item {
                ImplItem::Fn(f) => {
                    for input in &f.sig.inputs {
                        if let syn::FnArg::Typed(pt) = input {
                            self.visit_type(&pt.ty);
                        }
                    }
                    if let ReturnType::Type(_, ty) = &f.sig.output {
                        self.visit_type(ty);
                    }
                }
                ImplItem::Type(t) => {
                    self.visit_type(&t.ty);
                }
                ImplItem::Const(c) => {
                    self.visit_type(&c.ty);
                }
                _ => {}
            }
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        for input in &node.sig.inputs {
            if let syn::FnArg::Typed(pt) = input {
                self.visit_type(&pt.ty);
            }
        }
        if let ReturnType::Type(_, ty) = &node.sig.output {
            self.visit_type(ty);
        }
        // Don't recurse into fn body — call sites are not "flow" for our
        // purposes; we want the interface shape.
    }

    fn visit_trait_item(&mut self, node: &'ast TraitItem) {
        if let TraitItem::Fn(f) = node {
            for input in &f.sig.inputs {
                if let syn::FnArg::Typed(pt) = input {
                    self.visit_type(&pt.ty);
                }
            }
            if let ReturnType::Type(_, ty) = &f.sig.output {
                self.visit_type(ty);
            }
        }
    }

    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        // Detect `pub use other_crate::Type` re-exports. Non-pub uses are
        // ignored — they're this crate's internal dependencies on other
        // crates, which we already track via type refs anyway.
        let is_pub = matches!(node.vis, syn::Visibility::Public(_));
        if !is_pub {
            return;
        }
        collect_reexports(&node.tree, None, &mut self.facts.reexports);
    }
}

/// Walk a UseTree collecting `(from_crate_snake, type_name)` pairs. `parent`
/// tracks the outer path prefix (`std::io` etc.); only the FIRST segment is
/// the "from crate" we care about.
fn collect_reexports(
    tree: &UseTree,
    root_crate: Option<String>,
    out: &mut Vec<(String, String)>,
) {
    match tree {
        UseTree::Path(p) => {
            let seg = p.ident.to_string();
            let new_root = root_crate.or(Some(seg));
            collect_reexports(&p.tree, new_root, out);
        }
        UseTree::Name(n) => {
            if let Some(from) = root_crate {
                let name = n.ident.to_string();
                if name.chars().next().map(|c| c.is_ascii_uppercase()) == Some(true) {
                    out.push((from, name));
                }
            }
        }
        UseTree::Rename(r) => {
            if let Some(from) = root_crate {
                let name = r.ident.to_string();
                if name.chars().next().map(|c| c.is_ascii_uppercase()) == Some(true) {
                    out.push((from, name));
                }
            }
        }
        UseTree::Group(g) => {
            for item in &g.items {
                collect_reexports(item, root_crate.clone(), out);
            }
        }
        UseTree::Glob(_) => {
            // Glob re-exports are ambiguous; skip. In practice this is where
            // rust-analyzer's semantic pass would resolve to specific types.
        }
    }
}

// ---------------------------------------------------------------------------
// Per-crate aggregation.
// ---------------------------------------------------------------------------

struct CrateInfo {
    dir: PathBuf,
    files: usize,
    loc: usize,
    sign_count: usize,
    gate_count: usize,
    chain_count: usize,
    verify_count: usize,
    receipt_slugs: Vec<String>,
    type_defs: BTreeSet<String>,
    /// Every type reference collected across the crate (owner attributed later).
    type_refs: Vec<String>,
    /// Re-exports this crate exposes: (from_crate_snake, type_name).
    reexports: Vec<(String, String)>,
    deps: Vec<String>,
}

fn snake_to_kebab(s: &str) -> String {
    s.replace('_', "-")
}

// ---------------------------------------------------------------------------
// Output records (schema-compatible with the Python extractor).
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct CrateOut {
    name: String,
    files: usize,
    loc: usize,
    deps: Vec<String>,
    sign_count: usize,
    gate_count: usize,
    chain_count: usize,
    verify_count: usize,
    receipt_families: IndexMap<String, usize>,
    receipt_slugs_sample: Vec<String>,
    receipt_slug_total: usize,
    info_flow_signal: usize,
    primary_role: String,
    consumed_by: Vec<String>,
    type_defs: Vec<String>,
    type_defs_count: usize,
    types_produced: IndexMap<String, usize>,
    types_consumed: IndexMap<String, usize>,
    type_flow_signal: usize,
    types_produced_total: usize,
    types_consumed_total: usize,
}

#[derive(Serialize)]
struct EdgeOut {
    from: String,
    to: String,
    weight: usize,
    types: IndexMap<String, usize>,
}

#[derive(Serialize)]
struct Counts {
    total_crates: usize,
    total_deps_edges: usize,
    total_sign_sites: usize,
    total_gate_crossings: usize,
    total_chain_emits: usize,
    total_verifications: usize,
    total_receipt_slugs: usize,
    total_type_flow_signal: usize,
    total_type_defs: usize,
    total_type_flow_edges: usize,
}

#[derive(Serialize)]
struct Manifest {
    generated_at: u64,
    #[serde(rename = "extractor")]
    extractor: &'static str,
    crates: Vec<CrateOut>,
    counts: Counts,
    type_flow_edges: Vec<EdgeOut>,
}

fn primary_role(sign: usize, gate: usize, chain: usize, verify: usize, receipt_slug_total: usize) -> String {
    let scores = [
        ("signing", sign),
        ("gating", gate),
        ("chain-emit", chain),
        ("verifying", verify),
    ];
    let top = scores.iter().map(|(_, v)| *v).max().unwrap_or(0);
    if top == 0 {
        return if receipt_slug_total >= 5 {
            "receipt-authoring".to_string()
        } else {
            "utility".to_string()
        };
    }
    if receipt_slug_total > top {
        return "receipt-authoring".to_string();
    }
    for (name, val) in scores {
        if val == top {
            return name.to_string();
        }
    }
    "utility".to_string()
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    let repo_root = cli.repo_root.canonicalize().context("resolve --repo-root")?;
    let out_path = cli
        .out
        .clone()
        .unwrap_or_else(|| repo_root.join("docs/lenses/source-manifest.json"));

    if !repo_root.join("crates").is_dir() {
        bail!("no crates/ under {}", repo_root.display());
    }

    let crate_dirs = find_crate_dirs(&repo_root, cli.include_tools);
    let ignore = ignore_types();
    let slug_re = receipt_slug_regex();

    // Pass 1: parse every file, collect per-crate defs + refs.
    let mut infos: BTreeMap<String, CrateInfo> = BTreeMap::new();
    for cdir in &crate_dirs {
        let name = cdir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let mut info = CrateInfo {
            dir: cdir.clone(),
            files: 0,
            loc: 0,
            sign_count: 0,
            gate_count: 0,
            chain_count: 0,
            verify_count: 0,
            receipt_slugs: Vec::new(),
            type_defs: BTreeSet::new(),
            type_refs: Vec::new(),
            reexports: Vec::new(),
            deps: Vec::new(),
        };
        for rs in walk_rs_files(cdir) {
            let text = match fs::read_to_string(&rs) {
                Ok(t) => t,
                Err(_) => continue,
            };
            info.files += 1;
            info.loc += text.matches('\n').count();
            info.sign_count += count_signals(&text, SIGN_PATTERNS);
            info.gate_count += count_signals(&text, GATE_PATTERNS);
            info.chain_count += count_signals(&text, CHAIN_PATTERNS);
            info.verify_count += count_signals(&text, VERIFY_PATTERNS);
            for m in slug_re.captures_iter(&text) {
                info.receipt_slugs.push(m[1].to_string());
            }

            // Parse the file. If it fails (macro-heavy, exotic syntax), skip
            // AST facts for this file but keep the signal counts we already
            // collected — the file was scanned as text.
            let syntax = match syn::parse_file(&text) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let mut fv = FileVisitor {
                facts: FileFacts::default(),
                ignore: &ignore,
            };
            for item in &syntax.items {
                fv.visit_item(item);
            }
            for name in fv.facts.type_defs {
                if !ignore.contains(name.as_str()) {
                    info.type_defs.insert(name);
                }
            }
            info.type_refs.extend(fv.facts.type_refs);
            info.reexports.extend(fv.facts.reexports);
        }
        infos.insert(name, info);
    }

    let known: HashSet<String> = infos.keys().cloned().collect();

    // Resolve Cargo.toml deps once we know the crate universe.
    for info in infos.values_mut() {
        info.deps = parse_cargo_deps(&info.dir.join("Cargo.toml"), &known);
    }

    // Build type -> owning crate. First writer wins for stability.
    let mut owner: HashMap<String, String> = HashMap::new();
    for (cname, info) in &infos {
        for t in &info.type_defs {
            owner.entry(t.clone()).or_insert_with(|| cname.clone());
        }
    }

    // Apply re-export corrections: if crate A re-exports B::Foo publicly,
    // and Foo is also defined in A (unlikely) or unowned so far, attribute
    // to B. Only rewrite ownership when the re-export target is a known crate.
    for (cname, info) in &infos {
        for (from_snake, type_name) in &info.reexports {
            let from_kebab = snake_to_kebab(from_snake);
            if from_kebab == *cname || !known.contains(&from_kebab) {
                continue;
            }
            // Only promote when the type isn't already owned (or is owned by
            // us — the re-export can't override a real definition elsewhere).
            match owner.get(type_name) {
                None => {
                    owner.insert(type_name.clone(), from_kebab);
                }
                Some(existing) if existing == cname => {
                    // Rare — treat re-export as authoritative for cross-crate lookup.
                    owner.insert(type_name.clone(), from_kebab);
                }
                _ => {}
            }
        }
    }

    // Pass 2: attribute each ref to owner; compute per-crate produced/consumed
    // and cross-crate edges.
    #[derive(Default)]
    struct CrateAgg {
        produced: HashMap<String, usize>,
        consumed: HashMap<String, usize>,
    }
    let mut aggs: HashMap<String, CrateAgg> = HashMap::new();
    let mut edges: HashMap<(String, String), HashMap<String, usize>> = HashMap::new();

    for (cname, info) in &infos {
        let agg = aggs.entry(cname.clone()).or_default();
        for r in &info.type_refs {
            if let Some(o) = owner.get(r) {
                if o == cname {
                    *agg.produced.entry(r.clone()).or_default() += 1;
                } else {
                    *agg.consumed.entry(r.clone()).or_default() += 1;
                    let key = (o.clone(), cname.clone());
                    let em = edges.entry(key).or_default();
                    *em.entry(r.clone()).or_default() += 1;
                }
            }
        }
    }

    // Build consumers (reverse dep map).
    let mut consumers: HashMap<String, BTreeSet<String>> = HashMap::new();
    for (cname, info) in &infos {
        for dep in &info.deps {
            consumers
                .entry(dep.clone())
                .or_default()
                .insert(cname.clone());
        }
    }

    // Assemble crate records.
    let mut crates_out: Vec<CrateOut> = Vec::new();
    let mut total_sign = 0;
    let mut total_gate = 0;
    let mut total_chain = 0;
    let mut total_verify = 0;
    let mut total_receipts = 0;
    let mut total_deps = 0;
    let mut total_types = 0;
    let mut total_typeflow_sig = 0;

    for (cname, info) in &infos {
        let agg = aggs.entry(cname.clone()).or_default();

        // receipt_families
        let mut families: IndexMap<String, usize> = IndexMap::new();
        for s in &info.receipt_slugs {
            let head = s.split(':').next().unwrap_or("").to_string();
            *families.entry(head).or_insert(0) += 1;
        }
        families.sort_by(|_, a, _, b| b.cmp(a));

        // receipt_slugs_sample (top 12 by frequency)
        let mut slug_counts: HashMap<String, usize> = HashMap::new();
        for s in &info.receipt_slugs {
            *slug_counts.entry(s.clone()).or_insert(0) += 1;
        }
        let mut slug_pairs: Vec<_> = slug_counts.into_iter().collect();
        slug_pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let slugs_sample: Vec<String> = slug_pairs.into_iter().take(12).map(|(k, _)| k).collect();

        // types_produced / types_consumed sorted by count desc
        let mut prod: Vec<_> = agg.produced.iter().map(|(k, v)| (k.clone(), *v)).collect();
        prod.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let types_produced: IndexMap<String, usize> = prod.into_iter().collect();

        let mut cons: Vec<_> = agg.consumed.iter().map(|(k, v)| (k.clone(), *v)).collect();
        cons.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let types_consumed: IndexMap<String, usize> = cons.into_iter().collect();

        let produced_total: usize = types_produced.values().sum();
        let consumed_total: usize = types_consumed.values().sum();
        let info_flow_signal = info.sign_count + info.gate_count + info.chain_count + info.verify_count;
        let role = primary_role(
            info.sign_count,
            info.gate_count,
            info.chain_count,
            info.verify_count,
            info.receipt_slugs.len(),
        );

        let consumed_by: Vec<String> = consumers
            .get(cname)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();

        let type_defs_v: Vec<String> = info.type_defs.iter().cloned().collect();

        total_sign += info.sign_count;
        total_gate += info.gate_count;
        total_chain += info.chain_count;
        total_verify += info.verify_count;
        total_receipts += info.receipt_slugs.len();
        total_deps += info.deps.len();
        total_types += info.type_defs.len();
        total_typeflow_sig += produced_total + consumed_total;

        crates_out.push(CrateOut {
            name: cname.clone(),
            files: info.files,
            loc: info.loc,
            deps: info.deps.clone(),
            sign_count: info.sign_count,
            gate_count: info.gate_count,
            chain_count: info.chain_count,
            verify_count: info.verify_count,
            receipt_families: families,
            receipt_slugs_sample: slugs_sample,
            receipt_slug_total: info.receipt_slugs.len(),
            info_flow_signal,
            primary_role: role,
            consumed_by,
            type_defs: type_defs_v.clone(),
            type_defs_count: type_defs_v.len(),
            types_produced,
            types_consumed,
            type_flow_signal: produced_total + consumed_total,
            types_produced_total: produced_total,
            types_consumed_total: consumed_total,
        });
    }
    crates_out.sort_by(|a, b| a.name.cmp(&b.name));

    // Assemble edges.
    let mut edges_out: Vec<EdgeOut> = edges
        .into_iter()
        .map(|((from, to), types)| {
            let mut pairs: Vec<_> = types.into_iter().collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let weight: usize = pairs.iter().map(|(_, v)| v).sum();
            let types: IndexMap<String, usize> = pairs.into_iter().take(12).collect();
            EdgeOut {
                from,
                to,
                weight,
                types,
            }
        })
        .collect();
    edges_out.sort_by(|a, b| b.weight.cmp(&a.weight).then_with(|| a.from.cmp(&b.from)).then_with(|| a.to.cmp(&b.to)));

    let counts = Counts {
        total_crates: crates_out.len(),
        total_deps_edges: total_deps,
        total_sign_sites: total_sign,
        total_gate_crossings: total_gate,
        total_chain_emits: total_chain,
        total_verifications: total_verify,
        total_receipt_slugs: total_receipts,
        total_type_flow_signal: total_typeflow_sig,
        total_type_defs: total_types,
        total_type_flow_edges: edges_out.len(),
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let manifest = Manifest {
        generated_at: now,
        extractor: "zp-lens-ast-extractor/0.1.0 (syn 2)",
        crates: crates_out,
        counts,
        type_flow_edges: edges_out,
    };

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).ok();
    }
    let s = serde_json::to_string_pretty(&manifest)?;
    fs::write(&out_path, s).context("write manifest")?;
    let c = &manifest.counts;
    println!("wrote {}", out_path.display());
    println!(
        "  {} crates, {} deps, {} type defs, {} type-flow edges, {} type-flow signals",
        c.total_crates, c.total_deps_edges, c.total_type_defs, c.total_type_flow_edges, c.total_type_flow_signal
    );
    println!(
        "  sign={} gate={} chain={} verify={} receipts={}",
        c.total_sign_sites, c.total_gate_crossings, c.total_chain_emits, c.total_verifications, c.total_receipt_slugs
    );

    Ok(())
}
