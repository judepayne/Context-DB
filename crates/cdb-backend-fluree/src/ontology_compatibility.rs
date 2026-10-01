//! Deterministic, read-only compatibility analysis for caller-supplied Turtle.
//!
//! This module deliberately has no ledger, cache, sandbox, or network surface.
//! Imports are followed only through the caller's explicit local map.

use crate::authorized_view::{ExactTerm, RdfNodeId, SourceQuad};
use crate::ontology_profile_v2::{
    analyze_ontology_bundle_v2, OntologyIssueClass, OntologyProfileLimits, ONTOLOGY_PROFILE_V2_ID,
};
use cdb_core::id::ContentHash;
use fluree_graph_ir::{Datatype, GraphCollectorSink, Term};
use fluree_graph_turtle::{parse_with_options, ParserOptions};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Component, Path, PathBuf};

const OWL_IMPORTS: &str = "http://www.w3.org/2002/07/owl#imports";
const OWL_ONTOLOGY: &str = "http://www.w3.org/2002/07/owl#Ontology";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
pub const FLUREE_REVISION: &str = crate::backend_identity::FLUREE_REVISION;
pub const ANALYZER_ID: &str = "ctxql-local-ontology-compatibility/v1";
const MAX_REPORTED_LOCATION_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatibilityLimits {
    pub max_files: usize,
    pub max_bytes: usize,
    pub max_triples: usize,
    pub max_import_depth: usize,
    pub max_list_length: usize,
    pub max_expression_depth: usize,
    pub max_diagnostics: usize,
    pub max_report_bytes: usize,
}

impl Default for CompatibilityLimits {
    fn default() -> Self {
        Self {
            max_files: 1_000,
            max_bytes: 64 * 1024 * 1024,
            max_triples: 500_000,
            max_import_depth: 64,
            max_list_length: 10_000,
            max_expression_depth: 10,
            max_diagnostics: 128,
            max_report_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompatibilityOptions {
    /// Absolute root. Every input and import target must resolve beneath it.
    pub root: PathBuf,
    /// Absolute paths beneath `root`, or relative paths explicitly rooted at `root`.
    pub inputs: Vec<PathBuf>,
    pub entry_ontology_iris: Vec<String>,
    /// Ontology IRI to absolute/root-relative local Turtle path.
    pub import_map: BTreeMap<String, PathBuf>,
    pub limits: CompatibilityLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityErrorKind {
    Invocation,
    Io,
    Limit,
    Serialization,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityError {
    pub kind: CompatibilityErrorKind,
    pub public_code: &'static str,
}

impl std::fmt::Display for CompatibilityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.public_code)
    }
}

impl std::error::Error for CompatibilityError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Compatible,
    Unsupported,
    Malformed,
    MissingImport,
    ImportCycle,
    Limit,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct CompatibilityDiagnostic {
    pub category: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct CompatibilityFile {
    pub location: String,
    pub sha256: String,
    pub bytes: usize,
    pub triples: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct CompatibilityImportEdge {
    pub from: String,
    pub ontology_iri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompatibilityLimitReport {
    pub max_files: usize,
    pub max_bytes: usize,
    pub max_triples: usize,
    pub max_import_depth: usize,
    pub max_list_length: usize,
    pub max_expression_depth: usize,
    pub max_diagnostics: usize,
    pub max_report_bytes: usize,
    pub observed_files: usize,
    pub observed_bytes: usize,
    pub observed_triples: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exceeded: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompatibilityReport {
    pub analyzer_identity: String,
    pub fluree_revision: String,
    pub profile_identity: String,
    pub accepted_serializations: Vec<String>,
    pub loader_requirement: String,
    pub status: CompatibilityStatus,
    pub compatible: bool,
    pub entry_ontology_iris: Vec<String>,
    pub files: Vec<CompatibilityFile>,
    pub import_edges: Vec<CompatibilityImportEdge>,
    pub construct_counts: BTreeMap<String, usize>,
    pub rule_counts: BTreeMap<String, usize>,
    pub category_counts: BTreeMap<String, usize>,
    pub diagnostics: Vec<CompatibilityDiagnostic>,
    pub full_bundle_root: Option<String>,
    pub profile_result_root: Option<String>,
    pub limits: CompatibilityLimitReport,
}

impl CompatibilityReport {
    pub fn is_compatible(&self) -> bool {
        self.compatible
    }
}

#[derive(Clone)]
struct ParsedFile {
    report: CompatibilityFile,
    quads: BTreeSet<SourceQuad>,
    imports: Vec<String>,
}

/// Analyze local Turtle without opening a ledger or performing any network I/O.
pub fn analyze_local_ontology(
    options: &CompatibilityOptions,
) -> Result<CompatibilityReport, CompatibilityError> {
    validate_limits(options.limits)?;
    let root = canonical_root(&options.root)?;
    let import_map = normalize_import_map(&root, &options.import_map)?;
    let mut seeds = collect_inputs(&root, &options.inputs, options.limits.max_files)?;
    seeds.sort();
    seeds.dedup();
    if seeds.is_empty() {
        return Err(error(
            CompatibilityErrorKind::Invocation,
            "ontology_input_required",
        ));
    }

    let mut queue: VecDeque<(PathBuf, usize)> = seeds.into_iter().map(|path| (path, 0)).collect();
    let mut depths: BTreeMap<PathBuf, usize> = BTreeMap::new();
    let mut parsed: BTreeMap<PathBuf, ParsedFile> = BTreeMap::new();
    let mut edges = BTreeSet::new();
    let mut observed_bytes = 0usize;
    let mut observed_triples = 0usize;

    while let Some((path, depth)) = queue.pop_front() {
        if let Some(previous) = depths.get(&path) {
            if *previous <= depth {
                continue;
            }
        }
        if depth > options.limits.max_import_depth {
            return bounded_failure(
                options,
                &root,
                parsed,
                edges,
                observed_bytes,
                observed_triples,
                CompatibilityStatus::Limit,
                "import_depth_limit_exceeded",
                Some("max_import_depth"),
            );
        }
        depths.insert(path.clone(), depth);
        if !parsed.contains_key(&path) {
            if parsed.len() >= options.limits.max_files {
                return bounded_failure(
                    options,
                    &root,
                    parsed,
                    edges,
                    observed_bytes,
                    observed_triples,
                    CompatibilityStatus::Limit,
                    "file_limit_exceeded",
                    Some("max_files"),
                );
            }
            let file = parse_file(
                &root,
                &path,
                options.limits,
                &mut observed_bytes,
                &mut observed_triples,
            )?;
            parsed.insert(path.clone(), file);
        }
        let imports = parsed[&path].imports.clone();
        let from = relative_location(&root, &path)?;
        for iri in imports {
            if let Some(target) = import_map.get(&iri) {
                let to = relative_location(&root, target)?;
                edges.insert((from.clone(), iri, Some(to)));
                queue.push_back((target.clone(), depth + 1));
            } else {
                edges.insert((from.clone(), iri.clone(), None));
                let reason = if is_remote_iri(&iri) {
                    "remote_import_not_mapped"
                } else {
                    "unresolved_import"
                };
                return bounded_failure(
                    options,
                    &root,
                    parsed,
                    edges,
                    observed_bytes,
                    observed_triples,
                    CompatibilityStatus::MissingImport,
                    reason,
                    None,
                );
            }
        }
    }

    if import_cycle(&root, &parsed, &import_map)? {
        return bounded_failure(
            options,
            &root,
            parsed,
            edges,
            observed_bytes,
            observed_triples,
            CompatibilityStatus::ImportCycle,
            "import_cycle",
            None,
        );
    }

    let mut bundle = BTreeSet::new();
    for file in parsed.values() {
        bundle.extend(file.quads.iter().cloned());
    }
    let mut entries = options.entry_ontology_iris.clone();
    entries.sort();
    entries.dedup();
    if let Some(missing) = entries
        .iter()
        .find(|entry| !declares_ontology(&bundle, entry))
    {
        let _ = missing;
        return bounded_failure(
            options,
            &root,
            parsed,
            edges,
            observed_bytes,
            observed_triples,
            CompatibilityStatus::Malformed,
            "entry_ontology_not_declared",
            None,
        );
    }

    let profile_limits = OntologyProfileLimits {
        max_bundle_quads: options.limits.max_triples,
        max_list_length: options.limits.max_list_length,
        max_expression_depth: options.limits.max_expression_depth,
        max_diagnostics: options.limits.max_diagnostics,
    };
    match analyze_ontology_bundle_v2(&bundle, profile_limits) {
        Ok(profile) => {
            let counts = profile.construct_counts.clone();
            let rules = native_rule_counts(&bundle);
            let mut categories = BTreeMap::new();
            categories.insert("compatible".into(), bundle.len());
            let report = base_report(
                options,
                &root,
                parsed,
                edges,
                observed_bytes,
                observed_triples,
                CompatibilityStatus::Compatible,
                Vec::new(),
                counts,
                rules,
                categories,
                None,
            )
            .with_roots(
                profile.full_bundle_root.as_str(),
                profile.result_root.as_str(),
            );
            ensure_report_bound(report, options.limits.max_report_bytes)
        }
        Err(failure) => {
            let status = match failure.issues.first().map(|issue| issue.class) {
                Some(OntologyIssueClass::Unsupported) => CompatibilityStatus::Unsupported,
                Some(OntologyIssueClass::Limit) => CompatibilityStatus::Limit,
                _ => CompatibilityStatus::Malformed,
            };
            let mut diagnostics = failure
                .issues
                .into_iter()
                .take(options.limits.max_diagnostics)
                .map(|issue| CompatibilityDiagnostic {
                    category: issue_category(issue.class).into(),
                    reason: issue.reason.into(),
                    location: issue
                        .graph
                        .and_then(|graph| graph_location(&parsed, &graph)),
                    predicate: issue.predicate,
                })
                .collect::<Vec<_>>();
            diagnostics.sort();
            let mut categories = BTreeMap::new();
            categories.insert(issue_category_for_status(&status).into(), diagnostics.len());
            let exceeded =
                matches!(status, CompatibilityStatus::Limit).then(|| "profile_limit".to_owned());
            let report = base_report(
                options,
                &root,
                parsed,
                edges,
                observed_bytes,
                observed_triples,
                status,
                diagnostics,
                BTreeMap::new(),
                BTreeMap::new(),
                categories,
                exceeded,
            );
            ensure_report_bound(report, options.limits.max_report_bytes)
        }
    }
}

pub fn canonical_report_json(report: &CompatibilityReport) -> Result<Vec<u8>, CompatibilityError> {
    let mut bytes = serde_json::to_vec(report).map_err(|_| {
        error(
            CompatibilityErrorKind::Serialization,
            "report_serialization_failed",
        )
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

impl CompatibilityReport {
    fn with_roots(mut self, bundle: &str, result: &str) -> Self {
        self.full_bundle_root = Some(bundle.into());
        self.profile_result_root = Some(result.into());
        self
    }
}

fn parse_file(
    root: &Path,
    path: &Path,
    limits: CompatibilityLimits,
    observed_bytes: &mut usize,
    observed_triples: &mut usize,
) -> Result<ParsedFile, CompatibilityError> {
    require_turtle(path)?;
    let bytes =
        fs::read(path).map_err(|_| error(CompatibilityErrorKind::Io, "ontology_read_failed"))?;
    *observed_bytes = observed_bytes.saturating_add(bytes.len());
    if *observed_bytes > limits.max_bytes {
        return Err(error(
            CompatibilityErrorKind::Limit,
            "ontology_byte_limit_exceeded",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| error(CompatibilityErrorKind::Serialization, "turtle_malformed"))?;
    let mut sink = GraphCollectorSink::new();
    parse_with_options(text, &mut sink, ParserOptions::conformant())
        .map_err(|_| error(CompatibilityErrorKind::Serialization, "turtle_malformed"))?;
    let graph = sink.into_graph();
    *observed_triples = observed_triples.saturating_add(graph.len());
    if *observed_triples > limits.max_triples {
        return Err(error(
            CompatibilityErrorKind::Limit,
            "ontology_triple_limit_exceeded",
        ));
    }
    let location = relative_location(root, path)?;
    let hash = ContentHash::of_bytes(&bytes).as_str().to_owned();
    let scope = ContentHash::of_bytes(format!("{location}\0{hash}").as_bytes())
        .as_str()
        .trim_start_matches("sha256:")
        .to_owned();
    let graph_name = format!("urn:ctxql:ontology-file:{scope}");
    let mut quads = BTreeSet::new();
    for triple in graph.iter() {
        let subject = node(&triple.s, &scope)?;
        let Term::Iri(predicate) = &triple.p else {
            return Err(error(
                CompatibilityErrorKind::Serialization,
                "turtle_malformed",
            ));
        };
        quads.insert(SourceQuad {
            graph: graph_name.clone(),
            subject,
            predicate: predicate.to_string(),
            object: object(&triple.o, &scope),
        });
    }
    let mut imports = quads
        .iter()
        .filter(|quad| quad.predicate == OWL_IMPORTS)
        .filter_map(|quad| quad.object.as_iri().map(str::to_owned))
        .collect::<Vec<_>>();
    imports.sort();
    imports.dedup();
    Ok(ParsedFile {
        report: CompatibilityFile {
            location,
            sha256: hash,
            bytes: bytes.len(),
            triples: quads.len(),
        },
        quads,
        imports,
    })
}

fn node(term: &Term, scope: &str) -> Result<RdfNodeId, CompatibilityError> {
    match term {
        Term::Iri(value) => Ok(RdfNodeId::Iri(value.to_string())),
        Term::BlankNode(value) => Ok(RdfNodeId::ScopedBlankNode(format!(
            "_:ctxql-{scope}-{}",
            value.as_str()
        ))),
        Term::Literal { .. } => Err(error(
            CompatibilityErrorKind::Serialization,
            "turtle_malformed",
        )),
    }
}

fn object(term: &Term, scope: &str) -> ExactTerm {
    match term {
        Term::Iri(value) => ExactTerm::Iri(value.to_string()),
        Term::BlankNode(value) => {
            ExactTerm::ScopedBlankNode(format!("_:ctxql-{scope}-{}", value.as_str()))
        }
        Term::Literal {
            value,
            datatype,
            language,
        } => ExactTerm::Literal {
            lexical: value.lexical(),
            datatype: datatype_iri(datatype).into(),
            language: language.as_ref().map(ToString::to_string),
        },
    }
}

fn datatype_iri(datatype: &Datatype) -> &str {
    datatype.as_iri()
}

#[allow(clippy::too_many_arguments)]
fn base_report(
    options: &CompatibilityOptions,
    root: &Path,
    parsed: BTreeMap<PathBuf, ParsedFile>,
    edges: BTreeSet<(String, String, Option<String>)>,
    observed_bytes: usize,
    observed_triples: usize,
    status: CompatibilityStatus,
    mut diagnostics: Vec<CompatibilityDiagnostic>,
    construct_counts: BTreeMap<String, usize>,
    rule_counts: BTreeMap<String, usize>,
    category_counts: BTreeMap<String, usize>,
    exceeded: Option<String>,
) -> CompatibilityReport {
    let _ = root;
    let observed_files = parsed.len();
    let mut entries = options.entry_ontology_iris.clone();
    entries.sort();
    entries.dedup();
    diagnostics.sort();
    let files = parsed.values().map(|file| file.report.clone()).collect();
    let import_edges = edges
        .into_iter()
        .map(|(from, ontology_iri, to)| CompatibilityImportEdge {
            from,
            ontology_iri,
            to,
        })
        .collect();
    CompatibilityReport {
        analyzer_identity: ANALYZER_ID.into(),
        fluree_revision: FLUREE_REVISION.into(),
        profile_identity: ONTOLOGY_PROFILE_V2_ID.into(),
        accepted_serializations: vec!["turtle".into()],
        loader_requirement: "trusted loader must preserve the conformant rdf:first/rdf:rest spine; default indexed-list ingestion is not equivalent".into(),
        compatible: matches!(status, CompatibilityStatus::Compatible),
        status,
        entry_ontology_iris: entries,
        files,
        import_edges,
        rule_counts,
        construct_counts,
        category_counts,
        diagnostics,
        full_bundle_root: None,
        profile_result_root: None,
        limits: CompatibilityLimitReport {
            max_files: options.limits.max_files,
            max_bytes: options.limits.max_bytes,
            max_triples: options.limits.max_triples,
            max_import_depth: options.limits.max_import_depth,
            max_list_length: options.limits.max_list_length,
            max_expression_depth: options.limits.max_expression_depth,
            max_diagnostics: options.limits.max_diagnostics,
            max_report_bytes: options.limits.max_report_bytes,
            observed_files,
            observed_bytes,
            observed_triples,
            exceeded,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn bounded_failure(
    options: &CompatibilityOptions,
    root: &Path,
    parsed: BTreeMap<PathBuf, ParsedFile>,
    edges: BTreeSet<(String, String, Option<String>)>,
    observed_bytes: usize,
    observed_triples: usize,
    status: CompatibilityStatus,
    reason: &str,
    exceeded: Option<&str>,
) -> Result<CompatibilityReport, CompatibilityError> {
    let category = issue_category_for_status(&status).to_owned();
    let diagnostic = CompatibilityDiagnostic {
        category: category.clone(),
        reason: reason.into(),
        location: None,
        predicate: None,
    };
    let report = base_report(
        options,
        root,
        parsed,
        edges,
        observed_bytes,
        observed_triples,
        status,
        vec![diagnostic],
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::from([(category, 1)]),
        exceeded.map(str::to_owned),
    );
    ensure_report_bound(report, options.limits.max_report_bytes)
}

fn ensure_report_bound(
    report: CompatibilityReport,
    max_report_bytes: usize,
) -> Result<CompatibilityReport, CompatibilityError> {
    let bytes = canonical_report_json(&report)?;
    if bytes.len() > max_report_bytes {
        Err(error(
            CompatibilityErrorKind::Limit,
            "report_size_limit_exceeded",
        ))
    } else {
        Ok(report)
    }
}

fn validate_limits(limits: CompatibilityLimits) -> Result<(), CompatibilityError> {
    if limits.max_files == 0
        || limits.max_bytes == 0
        || limits.max_triples == 0
        || limits.max_list_length == 0
        || limits.max_expression_depth == 0
        || limits.max_diagnostics == 0
        || limits.max_report_bytes == 0
    {
        return Err(error(
            CompatibilityErrorKind::Invocation,
            "positive_limits_required",
        ));
    }
    Ok(())
}

fn canonical_root(root: &Path) -> Result<PathBuf, CompatibilityError> {
    if !root.is_absolute() {
        return Err(error(
            CompatibilityErrorKind::Invocation,
            "absolute_root_required",
        ));
    }
    let root = fs::canonicalize(root)
        .map_err(|_| error(CompatibilityErrorKind::Io, "ontology_root_unavailable"))?;
    if !root.is_dir() {
        return Err(error(
            CompatibilityErrorKind::Invocation,
            "ontology_root_not_directory",
        ));
    }
    Ok(root)
}

fn rooted_path(root: &Path, supplied: &Path) -> Result<PathBuf, CompatibilityError> {
    if supplied
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(error(
            CompatibilityErrorKind::Invocation,
            "outside_root_path_rejected",
        ));
    }
    let joined = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        root.join(supplied)
    };
    let canonical = fs::canonicalize(joined)
        .map_err(|_| error(CompatibilityErrorKind::Io, "ontology_path_unavailable"))?;
    if !canonical.starts_with(root) {
        return Err(error(
            CompatibilityErrorKind::Invocation,
            "outside_root_path_rejected",
        ));
    }
    Ok(canonical)
}

fn collect_inputs(
    root: &Path,
    inputs: &[PathBuf],
    max_files: usize,
) -> Result<Vec<PathBuf>, CompatibilityError> {
    if inputs.len() > max_files {
        return Err(error(
            CompatibilityErrorKind::Limit,
            "ontology_file_limit_exceeded",
        ));
    }
    let mut files = Vec::new();
    let mut pending = Vec::new();
    let mut discovered_entries = 0usize;
    let max_discovery_entries = max_files.saturating_mul(4);
    for input in inputs {
        pending.push(rooted_path(root, input)?);
    }
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| error(CompatibilityErrorKind::Io, "ontology_path_unavailable"))?;
        if metadata.file_type().is_symlink() {
            return Err(error(
                CompatibilityErrorKind::Invocation,
                "ontology_symlink_rejected",
            ));
        }
        if metadata.is_file() {
            require_turtle(&path)?;
            files.push(path);
            if files.len() > max_files {
                return Err(error(
                    CompatibilityErrorKind::Limit,
                    "ontology_file_limit_exceeded",
                ));
            }
        } else if metadata.is_dir() {
            let entries = fs::read_dir(&path)
                .map_err(|_| error(CompatibilityErrorKind::Io, "ontology_directory_read_failed"))?;
            let mut children = Vec::new();
            for entry in entries {
                discovered_entries = discovered_entries.checked_add(1).ok_or_else(|| {
                    error(
                        CompatibilityErrorKind::Limit,
                        "ontology_discovery_limit_exceeded",
                    )
                })?;
                if discovered_entries > max_discovery_entries {
                    return Err(error(
                        CompatibilityErrorKind::Limit,
                        "ontology_discovery_limit_exceeded",
                    ));
                }
                children.push(
                    entry
                        .map_err(|_| {
                            error(CompatibilityErrorKind::Io, "ontology_directory_read_failed")
                        })?
                        .path(),
                );
            }
            children.sort();
            children.reverse();
            pending.extend(children);
        } else {
            return Err(error(
                CompatibilityErrorKind::Invocation,
                "ontology_input_type_rejected",
            ));
        }
    }
    Ok(files)
}

fn normalize_import_map(
    root: &Path,
    supplied: &BTreeMap<String, PathBuf>,
) -> Result<BTreeMap<String, PathBuf>, CompatibilityError> {
    let mut normalized = BTreeMap::new();
    for (iri, path) in supplied {
        if iri.is_empty() || iri.chars().any(char::is_control) {
            return Err(error(
                CompatibilityErrorKind::Invocation,
                "invalid_import_iri",
            ));
        }
        let path = rooted_path(root, path)?;
        require_turtle(&path)?;
        if !path.is_file() {
            return Err(error(
                CompatibilityErrorKind::Invocation,
                "import_target_not_file",
            ));
        }
        normalized.insert(iri.clone(), path);
    }
    Ok(normalized)
}

fn require_turtle(path: &Path) -> Result<(), CompatibilityError> {
    if path.extension().and_then(|value| value.to_str()) != Some("ttl") {
        return Err(error(
            CompatibilityErrorKind::Invocation,
            "turtle_input_required",
        ));
    }
    Ok(())
}

fn relative_location(root: &Path, path: &Path) -> Result<String, CompatibilityError> {
    let relative = path.strip_prefix(root).map_err(|_| {
        error(
            CompatibilityErrorKind::Invocation,
            "outside_root_path_rejected",
        )
    })?;
    let location = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    if location.is_empty() || location.len() > MAX_REPORTED_LOCATION_BYTES {
        return Err(error(
            CompatibilityErrorKind::Limit,
            "reported_location_limit_exceeded",
        ));
    }
    Ok(location)
}

fn graph_location(parsed: &BTreeMap<PathBuf, ParsedFile>, graph: &str) -> Option<String> {
    parsed.values().find_map(|file| {
        file.quads
            .iter()
            .any(|quad| quad.graph == graph)
            .then(|| file.report.location.clone())
    })
}

fn declares_ontology(bundle: &BTreeSet<SourceQuad>, iri: &str) -> bool {
    bundle.iter().any(|quad| {
        quad.subject.as_iri() == Some(iri)
            && quad.predicate == RDF_TYPE
            && quad.object.as_iri() == Some(OWL_ONTOLOGY)
    })
}

fn import_cycle(
    root: &Path,
    parsed: &BTreeMap<PathBuf, ParsedFile>,
    import_map: &BTreeMap<String, PathBuf>,
) -> Result<bool, CompatibilityError> {
    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (path, file) in parsed {
        let from = relative_location(root, path)?;
        let targets = file
            .imports
            .iter()
            .filter_map(|iri| import_map.get(iri))
            .map(|target| relative_location(root, target))
            .collect::<Result<Vec<_>, _>>()?;
        adjacency.insert(from, targets);
    }
    fn visit(
        node: &str,
        adjacency: &BTreeMap<String, Vec<String>>,
        gray: &mut BTreeSet<String>,
        black: &mut BTreeSet<String>,
    ) -> bool {
        if gray.contains(node) {
            return true;
        }
        if black.contains(node) {
            return false;
        }
        gray.insert(node.into());
        if adjacency.get(node).is_some_and(|targets| {
            targets
                .iter()
                .any(|target| visit(target, adjacency, gray, black))
        }) {
            return true;
        }
        gray.remove(node);
        black.insert(node.into());
        false
    }
    let mut gray = BTreeSet::new();
    let mut black = BTreeSet::new();
    Ok(adjacency
        .keys()
        .any(|node| visit(node, &adjacency, &mut gray, &mut black)))
}

fn is_remote_iri(iri: &str) -> bool {
    iri.starts_with("http://") || iri.starts_with("https://")
}

fn native_rule_counts(bundle: &BTreeSet<SourceQuad>) -> BTreeMap<String, usize> {
    fn add(counts: &mut BTreeMap<String, usize>, rule: &str) {
        *counts.entry(rule.into()).or_insert(0) += 1;
    }

    let mut counts = BTreeMap::new();
    for quad in bundle {
        match quad.predicate.as_str() {
            "http://www.w3.org/2000/01/rdf-schema#subPropertyOf" => add(&mut counts, "prp-spo1"),
            "http://www.w3.org/2002/07/owl#propertyChainAxiom" => add(&mut counts, "prp-spo2"),
            "http://www.w3.org/2000/01/rdf-schema#domain" => add(&mut counts, "prp-dom"),
            "http://www.w3.org/2000/01/rdf-schema#range" => add(&mut counts, "prp-rng"),
            "http://www.w3.org/2002/07/owl#inverseOf" => add(&mut counts, "prp-inv"),
            "http://www.w3.org/2002/07/owl#hasKey" => add(&mut counts, "prp-key"),
            "http://www.w3.org/2000/01/rdf-schema#subClassOf" => add(&mut counts, "cax-sco"),
            "http://www.w3.org/2002/07/owl#equivalentClass" => add(&mut counts, "cax-eqc"),
            "http://www.w3.org/2002/07/owl#sameAs" => add(&mut counts, "eq-union"),
            "http://www.w3.org/2002/07/owl#hasValue" => {
                add(&mut counts, "cls-hv1");
                add(&mut counts, "cls-hv2");
            }
            "http://www.w3.org/2002/07/owl#someValuesFrom" => add(&mut counts, "cls-svf1"),
            "http://www.w3.org/2002/07/owl#allValuesFrom" => add(&mut counts, "cls-avf"),
            "http://www.w3.org/2002/07/owl#intersectionOf" => {
                add(&mut counts, "cls-int1");
                add(&mut counts, "cls-int2");
            }
            "http://www.w3.org/2002/07/owl#unionOf" => add(&mut counts, "cls-uni"),
            "http://www.w3.org/2002/07/owl#oneOf" => add(&mut counts, "cls-oo"),
            "http://www.w3.org/2002/07/owl#maxCardinality" => add(&mut counts, "cls-maxc2"),
            "http://www.w3.org/2002/07/owl#maxQualifiedCardinality" => {
                add(&mut counts, "cls-maxqc");
                add(&mut counts, "cls-maxqc3");
                add(&mut counts, "cls-maxqc4");
            }
            RDF_TYPE => match quad.object.as_iri() {
                Some("http://www.w3.org/2002/07/owl#SymmetricProperty") => {
                    add(&mut counts, "prp-symp")
                }
                Some("http://www.w3.org/2002/07/owl#TransitiveProperty") => {
                    add(&mut counts, "prp-trp")
                }
                Some("http://www.w3.org/2002/07/owl#FunctionalProperty") => {
                    add(&mut counts, "prp-fp")
                }
                Some("http://www.w3.org/2002/07/owl#InverseFunctionalProperty") => {
                    add(&mut counts, "prp-ifp")
                }
                _ => {}
            },
            _ => {}
        }
    }
    counts
}

fn issue_category(class: OntologyIssueClass) -> &'static str {
    match class {
        OntologyIssueClass::Unsupported => "unsupported",
        OntologyIssueClass::Malformed => "malformed",
        OntologyIssueClass::Incomplete => "incomplete",
        OntologyIssueClass::Limit => "limit",
    }
}

fn issue_category_for_status(status: &CompatibilityStatus) -> &'static str {
    match status {
        CompatibilityStatus::Compatible => "compatible",
        CompatibilityStatus::Unsupported => "unsupported",
        CompatibilityStatus::Malformed => "malformed",
        CompatibilityStatus::MissingImport => "missing_import",
        CompatibilityStatus::ImportCycle => "import_cycle",
        CompatibilityStatus::Limit => "limit",
    }
}

fn error(kind: CompatibilityErrorKind, public_code: &'static str) -> CompatibilityError {
    CompatibilityError { kind, public_code }
}
