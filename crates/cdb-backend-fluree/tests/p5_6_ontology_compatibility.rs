use cdb_backend_fluree::ontology_compatibility::{
    analyze_local_ontology, canonical_report_json, CompatibilityErrorKind, CompatibilityLimits,
    CompatibilityOptions, CompatibilityStatus, FLUREE_REVISION,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const PREFIXES: &str = r#"
@prefix ex: <http://example.org/> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
"#;

fn put(root: &Path, name: &str, body: &str) -> PathBuf {
    let path = root.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, format!("{PREFIXES}\n{body}")).unwrap();
    PathBuf::from(name)
}

fn options(root: &Path, inputs: Vec<PathBuf>) -> CompatibilityOptions {
    CompatibilityOptions {
        root: root.to_path_buf(),
        inputs,
        entry_ontology_iris: Vec::new(),
        import_map: BTreeMap::new(),
        limits: CompatibilityLimits::default(),
    }
}

#[test]
fn compatible_reports_are_canonical_order_independent_and_revision_bound() {
    let temp = TempDir::new().unwrap();
    let a = put(
        temp.path(),
        "a.ttl",
        "ex:ontology a owl:Ontology . ex:C rdfs:subClassOf ex:D .",
    );
    let b = put(
        temp.path(),
        "nested/b.ttl",
        "ex:chain owl:propertyChainAxiom (ex:p ex:q) .",
    );
    let mut left = options(temp.path(), vec![b.clone(), a.clone()]);
    left.entry_ontology_iris = vec!["http://example.org/ontology".into()];
    let mut right = options(temp.path(), vec![a, b]);
    right.entry_ontology_iris = left.entry_ontology_iris.clone();

    let left = analyze_local_ontology(&left).unwrap();
    let right = analyze_local_ontology(&right).unwrap();
    assert_eq!(left.status, CompatibilityStatus::Compatible);
    assert_eq!(left.fluree_revision, FLUREE_REVISION);
    assert_eq!(
        canonical_report_json(&left).unwrap(),
        canonical_report_json(&right).unwrap()
    );
    assert!(left.loader_requirement.contains("rdf:first/rdf:rest"));
    assert_eq!(left.rule_counts.get("prp-spo2"), Some(&1));
    assert!(left
        .files
        .iter()
        .all(|file| !file.location.starts_with('/')));
}

#[test]
fn blank_nodes_and_conformant_collection_spines_are_stable_across_roots() {
    fn report() -> Vec<u8> {
        let temp = TempDir::new().unwrap();
        let input = put(
            temp.path(),
            "same.ttl",
            "ex:chain owl:propertyChainAxiom (ex:p ex:q) . ex:R a owl:Restriction ; owl:onProperty ex:p ; owl:someValuesFrom ex:C .",
        );
        canonical_report_json(&analyze_local_ontology(&options(temp.path(), vec![input])).unwrap())
            .unwrap()
    }
    assert_eq!(report(), report());
}

#[test]
fn unsupported_and_malformed_are_distinct_production_profile_results() {
    let unsupported_root = TempDir::new().unwrap();
    let unsupported = put(
        unsupported_root.path(),
        "unsupported.ttl",
        "ex:p owl:equivalentProperty ex:q .",
    );
    let report =
        analyze_local_ontology(&options(unsupported_root.path(), vec![unsupported])).unwrap();
    assert_eq!(report.status, CompatibilityStatus::Unsupported);
    assert_eq!(
        report.diagnostics[0].reason,
        "ontology_reserved_semantic_unsupported"
    );

    let malformed_root = TempDir::new().unwrap();
    let malformed = put(
        malformed_root.path(),
        "malformed.ttl",
        "ex:chain owl:propertyChainAxiom _:head . _:head rdf:first ex:p .",
    );
    let report = analyze_local_ontology(&options(malformed_root.path(), vec![malformed])).unwrap();
    assert_eq!(report.status, CompatibilityStatus::Malformed);
    assert_eq!(
        report.diagnostics[0].location.as_deref(),
        Some("malformed.ttl")
    );
}

#[test]
fn imports_are_explicit_local_only_and_cycles_are_distinct() {
    let missing_root = TempDir::new().unwrap();
    let missing = put(
        missing_root.path(),
        "missing.ttl",
        "ex:a a owl:Ontology ; owl:imports <https://remote.invalid/ontology> .",
    );
    let report = analyze_local_ontology(&options(missing_root.path(), vec![missing])).unwrap();
    assert_eq!(report.status, CompatibilityStatus::MissingImport);
    assert_eq!(report.diagnostics[0].reason, "remote_import_not_mapped");

    let cycle_root = TempDir::new().unwrap();
    let a = put(
        cycle_root.path(),
        "a.ttl",
        "ex:a a owl:Ontology ; owl:imports ex:b .",
    );
    let b = put(
        cycle_root.path(),
        "b.ttl",
        "ex:b a owl:Ontology ; owl:imports ex:a .",
    );
    let mut cycle = options(cycle_root.path(), vec![a]);
    cycle
        .import_map
        .insert("http://example.org/a".into(), PathBuf::from("a.ttl"));
    cycle.import_map.insert("http://example.org/b".into(), b);
    let report = analyze_local_ontology(&cycle).unwrap();
    assert_eq!(report.status, CompatibilityStatus::ImportCycle);
}

#[test]
fn byte_triple_file_depth_list_expression_diagnostic_and_report_bounds_are_enforced() {
    let root = TempDir::new().unwrap();
    let a = put(
        root.path(),
        "a.ttl",
        "ex:a a owl:Ontology ; owl:imports ex:b . ex:chain owl:propertyChainAxiom (ex:p ex:q) .",
    );
    let b = put(root.path(), "b.ttl", "ex:b a owl:Ontology .");
    let mut base = options(root.path(), vec![a.clone()]);
    base.import_map.insert("http://example.org/b".into(), b);

    let mut bytes = base.clone();
    bytes.limits.max_bytes = 1;
    assert_eq!(
        analyze_local_ontology(&bytes).unwrap_err().public_code,
        "ontology_byte_limit_exceeded"
    );

    let mut triples = base.clone();
    triples.limits.max_triples = 1;
    assert_eq!(
        analyze_local_ontology(&triples).unwrap_err().public_code,
        "ontology_triple_limit_exceeded"
    );

    let mut files = base.clone();
    files.inputs.push(PathBuf::from("b.ttl"));
    files.limits.max_files = 1;
    assert_eq!(
        analyze_local_ontology(&files).unwrap_err().public_code,
        "ontology_file_limit_exceeded"
    );

    let mut depth = base.clone();
    depth.limits.max_import_depth = 0;
    assert_eq!(
        analyze_local_ontology(&depth).unwrap().status,
        CompatibilityStatus::Limit
    );

    let mut list = base.clone();
    list.limits.max_list_length = 1;
    assert_eq!(
        analyze_local_ontology(&list).unwrap().status,
        CompatibilityStatus::Limit
    );

    let mut expression = options(root.path(), vec![put(
        root.path(),
        "expression.ttl",
        "ex:R a owl:Restriction ; owl:onProperty [ owl:inverseOf ex:p ] ; owl:someValuesFrom ex:C .",
    )]);
    expression.limits.max_expression_depth = 1;
    assert_eq!(
        analyze_local_ontology(&expression).unwrap().status,
        CompatibilityStatus::Limit
    );

    let mut diagnostics = options(
        root.path(),
        vec![put(
            root.path(),
            "unsupported.ttl",
            "ex:p owl:equivalentProperty ex:q .",
        )],
    );
    diagnostics.limits.max_diagnostics = 1;
    assert_eq!(
        analyze_local_ontology(&diagnostics)
            .unwrap()
            .diagnostics
            .len(),
        1
    );

    let mut report = base;
    report.limits.max_report_bytes = 1;
    assert_eq!(
        analyze_local_ontology(&report).unwrap_err().public_code,
        "report_size_limit_exceeded"
    );
}

#[test]
fn outside_root_is_rejected_without_disclosing_the_path() {
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let secret = put(outside.path(), "secret.ttl", "ex:C rdfs:subClassOf ex:D .");
    let absolute_secret = outside.path().join(secret);
    let error =
        analyze_local_ontology(&options(root.path(), vec![absolute_secret.clone()])).unwrap_err();
    assert_eq!(error.kind, CompatibilityErrorKind::Invocation);
    assert_eq!(error.public_code, "outside_root_path_rejected");
    assert!(!error.to_string().contains(outside.path().to_str().unwrap()));
}

#[test]
fn directory_discovery_is_bounded_before_unbounded_collection() {
    let root = TempDir::new().unwrap();
    for index in 0..13 {
        fs::create_dir(root.path().join(format!("empty-{index}"))).unwrap();
    }
    let mut bounded = options(root.path(), vec![PathBuf::from(".")]);
    bounded.limits.max_files = 3;
    let error = analyze_local_ontology(&bounded)
        .expect_err("visited directory entries must share the file discovery bound");
    assert_eq!(error.kind, CompatibilityErrorKind::Limit);
    assert_eq!(error.public_code, "ontology_discovery_limit_exceeded");
}

#[test]
fn cli_is_non_mutating_nonzero_on_incompatibility_and_output_is_create_new() {
    let root = TempDir::new().unwrap();
    let input = put(root.path(), "input.ttl", "ex:C rdfs:subClassOf ex:D .");
    let before = fs::read(root.path().join(&input)).unwrap();
    let output = root.path().join("report.json");
    let binary = env!("CARGO_BIN_EXE_cdb-ontology-compat");
    let first = Command::new(binary)
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(first.status.success());
    assert_eq!(first.stdout, fs::read(&output).unwrap());
    assert_eq!(before, fs::read(root.path().join(&input)).unwrap());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);

    let second = Command::new(binary)
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8(second.stderr)
        .unwrap()
        .contains("report_output_create_failed"));

    let unsupported = put(
        root.path(),
        "unsupported.ttl",
        "ex:p owl:equivalentProperty ex:q .",
    );
    let incompatible = Command::new(binary)
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "--input",
            unsupported.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(incompatible.status.code(), Some(3));
    assert!(String::from_utf8(incompatible.stdout)
        .unwrap()
        .contains("\"status\":\"unsupported\""));
}
