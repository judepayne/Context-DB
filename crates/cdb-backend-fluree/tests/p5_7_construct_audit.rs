use cdb_backend_fluree::{
    authorized_view::SourceQuad,
    ontology_construct_audit::{
        audit_ontology_closure, build_audited_closure_from_conversions,
        build_audited_ontology_closure, ConstructAuditLimits, ConstructDisposition,
        ONTOLOGY_CONSTRUCT_INVENTORY_INCOMPLETE,
    },
    ontology_conversion::{convert_rdfxml, ConversionLimits, ConversionRequest, ConversionResult},
    ontology_dependency_universe::{
        ConversionPin, OntologyDependencyUniverse, OntologyOwnership, UniverseLimits,
    },
    ontology_release::{
        ArtifactClassification, ArtifactRole, CompleteInventory, InventoryEntry,
        RelativeSourcePath, ReleaseEvidence, ReleaseForm, SourceArtifactPin, SourceReleaseManifest,
    },
};
use cdb_core::id::ContentHash;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::Path,
};

fn path(value: &str) -> RelativeSourcePath {
    RelativeSourcePath::new(value).unwrap()
}

fn rdf(ontology: &str, body: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
 xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#"
 xmlns:owl="http://www.w3.org/2002/07/owl#"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema#" xmlns:ex="urn:test:">
 <owl:Ontology rdf:about="{ontology}"><owl:versionIRI rdf:resource="{ontology}/v1"/></owl:Ontology>
 {body}
</rdf:RDF>"#
    )
    .into_bytes()
}

fn class(role: ArtifactRole, media_type: &str) -> ArtifactClassification {
    ArtifactClassification::new(role, media_type).unwrap()
}

fn release(product: &str, file: &str, bytes: &[u8]) -> SourceReleaseManifest {
    let license = b"synthetic license";
    let notice = b"synthetic notice";
    let ontology_class = class(ArtifactRole::OntologyRdf, "application/rdf+xml");
    let entries = vec![
        InventoryEntry::new(
            path("LICENSE.txt"),
            ContentHash::of_bytes(license),
            license.len() as u64,
            class(ArtifactRole::License, "text/plain"),
        )
        .unwrap(),
        InventoryEntry::new(
            path("NOTICE.txt"),
            ContentHash::of_bytes(notice),
            notice.len() as u64,
            class(ArtifactRole::Notice, "text/plain"),
        )
        .unwrap(),
        InventoryEntry::new(
            path(file),
            ContentHash::of_bytes(bytes),
            bytes.len() as u64,
            ontology_class.clone(),
        )
        .unwrap(),
    ];
    SourceReleaseManifest::new(
        "Synthetic Publisher",
        product,
        "v1",
        ReleaseForm::SyntheticArtifacts,
        Some("v1".into()),
        None,
        None,
        None,
        None,
        vec![SourceArtifactPin::new(
            path(file),
            format!("https://example.test/{product}/v1/{file}"),
            "v1",
            ContentHash::of_bytes(bytes),
            bytes.len() as u64,
            ontology_class,
        )
        .unwrap()],
        vec![
            ReleaseEvidence::license(path("LICENSE.txt"), ContentHash::of_bytes(license)),
            ReleaseEvidence::notice(path("NOTICE.txt"), ContentHash::of_bytes(notice)),
        ],
        CompleteInventory::new(entries).unwrap(),
        Some("synthetic-extraction-limits/v1".into()),
        "synthetic immutable source",
    )
    .unwrap()
}

fn conversion(
    release: &SourceReleaseManifest,
    ontology: &str,
    file: &str,
    graph: &str,
    bytes: &[u8],
) -> ConversionResult {
    convert_rdfxml(ConversionRequest {
        authoritative_bytes: bytes,
        source_release_id: release.id().as_str(),
        source_file_id: file,
        base_iri: ontology,
        graph_iri: graph,
        limits: ConversionLimits::default(),
    })
    .unwrap()
}

fn owner(
    release: &SourceReleaseManifest,
    ontology: &str,
    file: &str,
    graph: &str,
    bytes: &[u8],
    conversion: &ConversionResult,
) -> OntologyOwnership {
    OntologyOwnership::new(
        ontology,
        format!("{ontology}/v1"),
        release.id().clone(),
        path(file),
        ContentHash::of_bytes(bytes),
        "application/rdf+xml",
        ConversionPin::from_result(conversion, bytes).unwrap(),
        graph,
        vec![],
    )
    .unwrap()
}

fn fixture(
    specs: &[(&str, &str, &str, &str, &str)],
) -> (
    OntologyDependencyUniverse,
    Vec<ConversionResult>,
    Vec<String>,
) {
    let mut releases = Vec::new();
    let mut owners = Vec::new();
    let mut conversions = Vec::new();
    let mut entries = Vec::new();
    for (product, ontology, file, graph, body) in specs {
        let bytes = rdf(ontology, body);
        let release = release(product, file, &bytes);
        let converted = conversion(&release, ontology, file, graph, &bytes);
        owners.push(owner(&release, ontology, file, graph, &bytes, &converted));
        releases.push(release);
        conversions.push(converted);
        entries.push((*ontology).to_owned());
    }
    let universe = OntologyDependencyUniverse::seal(
        releases,
        owners,
        vec![],
        "synthetic-exact/v1",
        "synthetic-limits/v1",
        "synthetic-analyzer/v1",
        "synthetic-resolver/v1",
        UniverseLimits::default(),
    )
    .unwrap();
    (universe, conversions, entries)
}

#[test]
fn closure_is_deterministic_and_preserves_duplicate_source_occurrences() {
    let common = r#"<rdf:Description rdf:about="urn:shared:subject">
      <rdfs:subClassOf rdf:resource="urn:shared:object"/>
    </rdf:Description>"#;
    let (universe, conversions, mut entries) = fixture(&[
        ("B", "urn:ontology:b", "b.rdf", "urn:graph:shared", common),
        ("A", "urn:ontology:a", "a.rdf", "urn:graph:shared", common),
    ]);
    let first = build_audited_ontology_closure(&universe, &entries, &conversions).unwrap();
    entries.reverse();
    let mut reversed_conversions = conversions.clone();
    reversed_conversions.reverse();
    let second =
        build_audited_ontology_closure(&universe, &entries, &reversed_conversions).unwrap();
    assert_eq!(first, second);

    let duplicates = first
        .occurrences
        .iter()
        .filter(|occurrence| {
            occurrence.subject.as_iri() == Some("urn:shared:subject")
                && occurrence.predicate == "http://www.w3.org/2000/01/rdf-schema#subClassOf"
        })
        .count();
    assert_eq!(duplicates, 2);
    assert!(first.bundle.len() < first.occurrences.len());
}

#[test]
fn collecting_audit_orders_all_issues_and_only_bounds_display_diagnostics() {
    let body = r#"
      <rdf:Description rdf:about="urn:z">
        <owl:equivalentProperty rdf:resource="urn:q"/>
      </rdf:Description>
      <rdf:Description rdf:about="urn:a">
        <rdfs:label rdf:resource="urn:not-a-literal"/>
      </rdf:Description>
      <rdf:Description rdf:about="urn:person">
        <rdf:type rdf:resource="http://www.w3.org/2002/07/owl#NamedIndividual"/>
      </rdf:Description>"#;
    let (universe, conversions, entries) = fixture(&[(
        "Issues",
        "urn:ontology:issues",
        "issues.rdf",
        "urn:graph:issues",
        body,
    )]);
    let closure = build_audited_ontology_closure(&universe, &entries, &conversions).unwrap();
    let small = ConstructAuditLimits {
        max_diagnostics: 1,
        ..ConstructAuditLimits::default()
    };
    let small_result = audit_ontology_closure(&closure, small).unwrap();
    let full_result = audit_ontology_closure(&closure, ConstructAuditLimits::default()).unwrap();

    assert!(small_result.complete);
    assert!(!small_result.accepted);
    assert_eq!(small_result.diagnostics.len(), 1);
    assert!(small_result.issues.len() >= 2);
    assert_eq!(small_result.issues, full_result.issues);
    assert_eq!(small_result.issue_root, full_result.issue_root);
    assert_eq!(
        small_result.bundle_classification_root,
        full_result.bundle_classification_root
    );
    assert!(small_result
        .issues
        .windows(2)
        .all(|pair| pair[0] <= pair[1]));
    assert!(small_result.entries.iter().any(|entry| {
        entry.disposition == ConstructDisposition::DeclarationCandidate
            && entry.quad.object.as_iri() == Some("http://www.w3.org/2002/07/owl#NamedIndividual")
    }));
    assert!(full_result.verify_integrity(&closure));
    let mut mutated_entry = full_result.clone();
    mutated_entry.entries[0].occurrence_identities[0] = ContentHash::of_bytes(b"mutated");
    assert!(!mutated_entry.verify_integrity(&closure));
    let mut mutated_occurrence = closure.clone();
    mutated_occurrence.occurrences[0].occurrence_identity = ContentHash::of_bytes(b"mutated");
    assert!(!full_result.verify_integrity(&mutated_occurrence));
}

#[test]
fn collecting_audit_covers_v2_expression_and_restriction_interactions() {
    let body = r#"
      <owl:Class rdf:about="urn:test:LiteralValueClass">
        <rdfs:subClassOf><owl:Restriction>
          <owl:onProperty rdf:resource="urn:test:p"/>
          <owl:hasValue>literal</owl:hasValue>
        </owl:Restriction></rdfs:subClassOf>
      </owl:Class>
      <owl:Class rdf:about="urn:test:QualifiedClass">
        <rdfs:subClassOf><owl:Restriction>
          <owl:onProperty rdf:resource="urn:test:p"/>
          <owl:maxQualifiedCardinality rdf:datatype="http://www.w3.org/2001/XMLSchema#nonNegativeInteger">1</owl:maxQualifiedCardinality>
          <owl:onClass><owl:Class/></owl:onClass>
        </owl:Restriction></rdfs:subClassOf>
      </owl:Class>
      <owl:Class rdf:about="urn:test:PropertyExpressionClass">
        <rdfs:subClassOf><owl:Restriction>
          <owl:onProperty><rdf:Description>
            <owl:inverseOf rdf:resource="urn:test:p"/>
            <owl:propertyChainAxiom rdf:parseType="Collection">
              <rdf:Description rdf:about="urn:test:p"/>
              <rdf:Description rdf:about="urn:test:q"/>
            </owl:propertyChainAxiom>
          </rdf:Description></owl:onProperty>
          <owl:someValuesFrom rdf:resource="urn:test:Target"/>
        </owl:Restriction></rdfs:subClassOf>
      </owl:Class>
      <owl:Class rdf:about="urn:test:ClassExpressionOwner">
        <owl:intersectionOf rdf:parseType="Collection">
          <rdf:Description>
            <owl:unionOf rdf:parseType="Collection">
              <owl:Class rdf:about="urn:test:A"/>
              <owl:Class rdf:about="urn:test:B"/>
            </owl:unionOf>
            <owl:oneOf rdf:parseType="Collection">
              <rdf:Description rdf:about="urn:test:a"/>
            </owl:oneOf>
          </rdf:Description>
        </owl:intersectionOf>
      </owl:Class>"#;
    let (universe, conversions, entries) = fixture(&[(
        "Interactions",
        "urn:ontology:interactions",
        "interactions.rdf",
        "urn:graph:interactions",
        body,
    )]);
    let closure = build_audited_ontology_closure(&universe, &entries, &conversions).unwrap();
    let audit = audit_ontology_closure(&closure, ConstructAuditLimits::default()).unwrap();
    let reasons = audit
        .issues
        .iter()
        .map(|issue| issue.reason)
        .collect::<BTreeSet<_>>();
    assert!(reasons.contains("ontology_literal_has_value_unsupported"));
    assert!(reasons.contains("ontology_qualified_cardinality_class_unsupported"));
    assert!(reasons.contains("ontology_property_expression_ambiguous"));
    assert!(reasons.contains("ontology_class_expression_ambiguous"));
}

#[test]
fn valid_unsupported_restriction_forms_are_not_marked_malformed() {
    let body = r#"
      <owl:Class rdf:about="urn:test:MinClass">
        <rdfs:subClassOf><owl:Restriction>
          <owl:onProperty rdf:resource="urn:test:p"/>
          <owl:minCardinality rdf:datatype="http://www.w3.org/2001/XMLSchema#nonNegativeInteger">0</owl:minCardinality>
        </owl:Restriction></rdfs:subClassOf>
      </owl:Class>
      <owl:Class rdf:about="urn:test:MinQualifiedClass">
        <rdfs:subClassOf><owl:Restriction>
          <owl:onProperty rdf:resource="urn:test:p"/>
          <owl:minQualifiedCardinality rdf:datatype="http://www.w3.org/2001/XMLSchema#nonNegativeInteger">1</owl:minQualifiedCardinality>
          <owl:onClass rdf:resource="urn:test:Target"/>
        </owl:Restriction></rdfs:subClassOf>
      </owl:Class>
      <owl:Class rdf:about="urn:test:DataQualifiedClass">
        <rdfs:subClassOf><owl:Restriction>
          <owl:onProperty rdf:resource="urn:test:data"/>
          <owl:qualifiedCardinality rdf:datatype="http://www.w3.org/2001/XMLSchema#nonNegativeInteger">1</owl:qualifiedCardinality>
          <owl:onDataRange><rdfs:Datatype>
            <owl:onDatatype rdf:resource="http://www.w3.org/2001/XMLSchema#decimal"/>
            <owl:withRestrictions rdf:parseType="Collection">
              <rdf:Description><xsd:minInclusive rdf:datatype="http://www.w3.org/2001/XMLSchema#decimal">0</xsd:minInclusive></rdf:Description>
            </owl:withRestrictions>
          </rdfs:Datatype></owl:onDataRange>
        </owl:Restriction></rdfs:subClassOf>
      </owl:Class>"#;
    let (universe, conversions, entries) = fixture(&[(
        "UnsupportedRestrictions",
        "urn:ontology:unsupported-restrictions",
        "unsupported.rdf",
        "urn:graph:unsupported",
        body,
    )]);
    let closure = build_audited_ontology_closure(&universe, &entries, &conversions).unwrap();
    let audit = audit_ontology_closure(&closure, ConstructAuditLimits::default()).unwrap();
    assert!(!audit.accepted);
    assert!(audit
        .issues
        .iter()
        .all(|issue| issue.class == ConstructDisposition::Unsupported));
    assert!(!audit.issues.iter().any(|issue| matches!(
        issue.reason,
        "ontology_restriction_kind_ambiguous" | "ontology_orphan_or_invalid_structural_node"
    )));
}

#[test]
fn complete_output_and_work_limits_fail_instead_of_returning_partial_results() {
    let (universe, conversions, entries) = fixture(&[(
        "Limits",
        "urn:ontology:limits",
        "limits.rdf",
        "urn:graph:limits",
        r#"<rdf:Description rdf:about="urn:a"><rdfs:subClassOf rdf:resource="urn:b"/></rdf:Description>"#,
    )]);
    let closure = build_audited_ontology_closure(&universe, &entries, &conversions).unwrap();

    let work = ConstructAuditLimits {
        max_structural_work: 1,
        ..ConstructAuditLimits::default()
    };
    let error = audit_ontology_closure(&closure, work).unwrap_err();
    assert_eq!(error.public_code, ONTOLOGY_CONSTRUCT_INVENTORY_INCOMPLETE);

    let output = ConstructAuditLimits {
        max_serialized_output_bytes: 1,
        ..ConstructAuditLimits::default()
    };
    let error = audit_ontology_closure(&closure, output).unwrap_err();
    assert_eq!(error.public_code, ONTOLOGY_CONSTRUCT_INVENTORY_INCOMPLETE);
}

#[test]
fn direct_conversion_universe_rejects_owner_and_import_substitution() {
    let ontology = "urn:ontology:direct";
    let bytes = rdf(
        ontology,
        r#"<rdf:Description rdf:about="urn:ontology:direct">
          <owl:imports rdf:resource="urn:ontology:missing"/>
        </rdf:Description>"#,
    );
    let release = release("Direct", "direct.rdf", &bytes);
    let converted = conversion(&release, ontology, "direct.rdf", "urn:graph:direct", &bytes);
    let pin = ConversionPin::from_result(&converted, &bytes).unwrap();
    let error = build_audited_closure_from_conversions(vec![(
        ontology.to_owned(),
        pin.clone(),
        converted.clone(),
    )])
    .unwrap_err();
    assert_eq!(error.reason, "dependency_ownership_map_invalid");

    let error = build_audited_closure_from_conversions(vec![(
        "urn:ontology:substituted".to_owned(),
        pin,
        converted,
    )])
    .unwrap_err();
    assert_eq!(error.reason, "dependency_ownership_map_invalid");
}

#[test]
fn conversion_source_and_closure_substitution_are_rejected() {
    let (universe, conversions, entries) = fixture(&[(
        "Substitution",
        "urn:ontology:substitution",
        "source.rdf",
        "urn:graph:source",
        "",
    )]);
    let mut substituted = conversions.clone();
    substituted[0].source_file_id = "other.rdf".into();
    let error = build_audited_ontology_closure(&universe, &entries, &substituted).unwrap_err();
    assert_eq!(error.public_code, ONTOLOGY_CONSTRUCT_INVENTORY_INCOMPLETE);

    let mut substituted = conversions.clone();
    substituted[0].conversion_root = ContentHash::of_bytes(b"substituted");
    let error = build_audited_ontology_closure(&universe, &entries, &substituted).unwrap_err();
    assert_eq!(error.reason, "ownership_conversion_mismatch");

    let mut closure = build_audited_ontology_closure(&universe, &entries, &conversions).unwrap();
    closure.occurrences[0].source_file_id = "substituted.rdf".into();
    let error = audit_ontology_closure(&closure, ConstructAuditLimits::default()).unwrap_err();
    assert_eq!(error.reason, "closure_integrity_mismatch");
}

#[derive(Deserialize)]
struct OfficialClosure {
    file_count: usize,
    total_authoritative_bytes: usize,
    inventory_root: String,
    files: Vec<OfficialFile>,
}

#[derive(Deserialize)]
struct OfficialFile {
    path: String,
    bytes: usize,
    sha256: String,
}

fn official_identity(file: &OfficialFile) -> (&'static str, String, String) {
    if let Some(name) = file
        .path
        .strip_prefix("commons/")
        .and_then(|path| path.strip_suffix(".rdf"))
    {
        (
            "sha256:07f8a4aba315edd5eb3373b406ea0b9bc48d1bd9d12c142206972f91b79785bb",
            format!("https://www.omg.org/spec/Commons/20250801/{name}.rdf"),
            format!("https://www.omg.org/spec/Commons/{name}/"),
        )
    } else {
        let relative = file.path.strip_prefix("fibo/").unwrap();
        let ontology = relative.strip_suffix(".rdf").unwrap();
        (
            "sha256:203a6a9d6e7a5d7ee855f299ad99a11ca5f1ac1d5e61f0ff293619d1526f13b2",
            format!("https://spec.edmcouncil.org/fibo/ontology/master/2026Q2/{relative}"),
            format!("https://spec.edmcouncil.org/fibo/ontology/{ontology}/"),
        )
    }
}

#[test]
#[ignore = "requires the exact external official ontology cache"]
fn official_relations_closure_audit_is_complete() {
    let root = std::env::var("CTXQL_P6_REFERENCE_CACHE")
        .expect("CTXQL_P6_REFERENCE_CACHE must name the absolute external cache");
    let root = Path::new(&root);
    assert!(root.is_absolute());
    let manifest: OfficialClosure = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/p5_7/official-relations-closure.json"
    ))
    .unwrap();
    assert_eq!(manifest.file_count, 19);
    assert_eq!(manifest.files.len(), 19);
    assert_eq!(manifest.total_authoritative_bytes, 385_886);
    assert_eq!(
        manifest.inventory_root,
        "sha256:d1a3bfb36743cc745b12f48bcdd2bfe01ba359643362682b04444ea36fc9b51d"
    );

    let mut total = 0usize;
    let mut inventory_material = Vec::new();
    let mut conversions = Vec::new();
    for file in &manifest.files {
        let bytes = fs::read(root.join(&file.path)).unwrap();
        assert_eq!(bytes.len(), file.bytes, "{} byte count", file.path);
        assert_eq!(
            &ContentHash::of_bytes(&bytes).as_str()[7..],
            file.sha256,
            "{} hash",
            file.path
        );
        total += bytes.len();
        inventory_material.extend_from_slice(file.path.as_bytes());
        inventory_material.push(0);
        inventory_material.extend_from_slice(file.sha256.as_bytes());
        inventory_material.push(b'\n');
        let (release, base, graph) = official_identity(file);
        let conversion = convert_rdfxml(ConversionRequest {
            authoritative_bytes: &bytes,
            source_release_id: release,
            source_file_id: &file.path,
            base_iri: &base,
            graph_iri: &graph,
            limits: ConversionLimits {
                max_input_bytes: 128 * 1024 * 1024,
                max_input_triples: 1_000_000,
                max_output_bytes: 256 * 1024 * 1024,
                max_blank_nodes: 200_000,
                max_canonicalization_work: 50_000_000,
            },
        })
        .unwrap_or_else(|error| panic!("{}: {error}", file.path));
        let pin = ConversionPin::from_result(&conversion, &bytes).unwrap();
        conversions.push((graph, pin, conversion));
    }
    assert_eq!(total, manifest.total_authoritative_bytes);
    assert_eq!(
        ContentHash::of_bytes(&inventory_material).as_str(),
        manifest.inventory_root
    );

    let closure = build_audited_closure_from_conversions(conversions).unwrap();
    let audit = audit_ontology_closure(
        &closure,
        ConstructAuditLimits {
            max_bundle_quads: 500_000,
            max_source_occurrences: 1_000_000,
            max_structural_work: 50_000_000,
            max_issues: 500_000,
            max_serialized_output_bytes: 256 * 1024 * 1024,
            ..ConstructAuditLimits::default()
        },
    )
    .unwrap();
    assert!(audit.complete);
    assert!(audit.verify_integrity(&closure));
    let reason_counts =
        audit
            .issues
            .iter()
            .fold(BTreeMap::<String, usize>::new(), |mut counts, issue| {
                *counts
                    .entry(format!("{:?}:{}", issue.class, issue.reason))
                    .or_default() += 1;
                counts
            });
    if let Ok(path) = std::env::var("CTXQL_P5_7_AUDIT_REPORT") {
        let report = json!({
            "schema": "ctxql.p5-7-official-construct-audit/v1",
            "scope": "FND/Relations/Relations",
            "file_count": manifest.file_count,
            "authoritative_bytes": total,
            "inventory_root": manifest.inventory_root,
            "complete": audit.complete,
            "accepted": audit.accepted,
            "bundle_quad_count": closure.bundle.len(),
            "source_occurrence_count": closure.occurrences.len(),
            "dependency_root": closure.dependency_root.as_str(),
            "closure_root": closure.closure_root.as_str(),
            "source_quad_root": closure.source_quad_root.as_str(),
            "source_entry_root": audit.source_entry_root.as_str(),
            "bundle_classification_root": audit.bundle_classification_root.as_str(),
            "issue_root": audit.issue_root.as_str(),
            "construct_audit_root": audit.construct_audit_root.as_str(),
            "category_counts": audit.category_counts.iter().map(|(category, count)|
                (format!("{category:?}"), *count)
            ).collect::<BTreeMap<_, _>>(),
            "category_roots": audit.category_roots.iter().map(|(category, root)|
                (format!("{category:?}"), root.as_str())
            ).collect::<BTreeMap<_, _>>(),
            "entries": audit.entries.iter().map(|entry| json!({
                "quad_commitment": ContentHash::of_bytes(entry.quad.commitment().as_bytes()).as_str(),
                "disposition": format!("{:?}", entry.disposition),
                "construct": entry.construct,
                "occurrence_identities": entry.occurrence_identities.iter()
                    .map(ContentHash::as_str).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "source_occurrences": closure.occurrences.iter().map(|occurrence| {
                let quad = SourceQuad {
                    graph: occurrence.graph.clone(),
                    subject: occurrence.subject.clone(),
                    predicate: occurrence.predicate.clone(),
                    object: occurrence.object.clone(),
                };
                json!({
                    "source_release_id": occurrence.source_release_id,
                    "source_file_id": occurrence.source_file_id,
                    "ontology_iri": occurrence.ontology_iri,
                    "conversion_root": occurrence.conversion_root.as_str(),
                    "quad_commitment": ContentHash::of_bytes(quad.commitment().as_bytes()).as_str(),
                    "occurrence_identity": occurrence.occurrence_identity.as_str(),
                })
            }).collect::<Vec<_>>(),
            "reason_counts": reason_counts,
            "issues": audit.issues.iter().map(|issue| json!({
                "source_release_id": issue.source_release_id,
                "source_file_id": issue.source_file_id,
                "ontology_iri": issue.ontology_iri,
                "diagnostic_commitment": ContentHash::of_bytes(format!(
                    "{}\0{}\0{}\0{}", issue.graph, issue.subject, issue.predicate, issue.object
                ).as_bytes()).as_str(),
                "class": format!("{:?}", issue.class),
                "reason": issue.reason,
                "stage": issue.stage,
            })).collect::<Vec<_>>(),
            "later_gates": {
                "profile_v3": "not_run",
                "declaration_parity": "not_run",
                "executable_profiles": "not_run",
                "load_reopen": "not_run"
            },
            "official_bytes_in_report": false,
            "legal_clearance": false,
        });
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("official audit report path must be create-new");
        output
            .write_all((serde_json::to_string_pretty(&report).unwrap() + "\n").as_bytes())
            .unwrap();
    }
    let declarations = audit
        .category_sets
        .get(&ConstructDisposition::DeclarationCandidate)
        .cloned()
        .unwrap_or_default();
    assert!(!declarations.is_empty());
    assert!(declarations.iter().all(|quad| {
        quad.subject.as_iri().is_some()
            && quad.predicate == "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
            && quad.object.as_iri() == Some("http://www.w3.org/2002/07/owl#NamedIndividual")
    }));
    println!(
        "P5_7_OFFICIAL_AUDIT files={} bytes={} quads={} occurrences={} declarations={} closure_root={} source_quad_root={} classification_root={} audit_root={}",
        manifest.file_count,
        total,
        closure.bundle.len(),
        closure.occurrences.len(),
        declarations.len(),
        closure.closure_root.as_str(),
        closure.source_quad_root.as_str(),
        audit.bundle_classification_root.as_str(),
        audit.construct_audit_root.as_str(),
    );
    assert_eq!(closure.bundle.len(), 3_503);
    assert_eq!(closure.occurrences.len(), 3_503);
    assert_eq!(
        closure.dependency_root.as_str(),
        "sha256:c688ba81a83bc9b60822d7bd21651c739540889e0ed8d2ef46c2c56ad59397e5"
    );
    assert_eq!(
        closure.closure_root.as_str(),
        "sha256:e29642fb4faf1d4acf46c329dda06e4d06a663e650616c5a5acef93714ebde48"
    );
    assert_eq!(
        closure.source_quad_root.as_str(),
        "sha256:c3babb9e258b8c70224b3a13f2106ad325bd648f77e563f1066ff44dcb1b9efb"
    );
    assert_eq!(
        audit.source_entry_root.as_str(),
        "sha256:a57ac2389c20d2cfe95ab0d236e2fd903290edff50ee05f389dbdcb20b599ae0"
    );
    assert_eq!(
        audit.bundle_classification_root.as_str(),
        "sha256:c090796819fc16560e477bc2295d910969254405096f48e30f1217da59c47758"
    );
    assert_eq!(
        audit.issue_root.as_str(),
        "sha256:2420b2f0825a23e823c6330e961038069579585d5d2b2d476c47b7120ea4eaac"
    );
    assert_eq!(
        audit.construct_audit_root.as_str(),
        "sha256:a56e7462d7516e8ffd9614a84df75a20de83fc533eda49696781fdfd4be56e85"
    );
    assert_eq!(
        audit.category_counts,
        BTreeMap::from([
            (ConstructDisposition::ReasonedCandidate, 2_904),
            (ConstructDisposition::DeclarationCandidate, 6),
            (ConstructDisposition::RetainedAnnotationCandidate, 502),
            (ConstructDisposition::Unsupported, 91),
        ])
    );
    assert_eq!(
        reason_counts,
        BTreeMap::from([
            (
                "Unsupported:ontology_reserved_semantic_unsupported".to_owned(),
                78,
            ),
            (
                "Unsupported:ontology_reserved_type_unsupported".to_owned(),
                7,
            ),
            (
                "Unsupported:ontology_reserved_term_unsupported".to_owned(),
                4,
            ),
            (
                "Unsupported:ontology_metadata_shape_unsupported".to_owned(),
                2,
            ),
        ])
    );
    assert!(!audit.accepted);
    assert_eq!(
        audit.category_sets.keys().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            ConstructDisposition::ReasonedCandidate,
            ConstructDisposition::DeclarationCandidate,
            ConstructDisposition::RetainedAnnotationCandidate,
            ConstructDisposition::Unsupported,
        ])
    );
}

#[test]
#[ignore = "requires the exact external Agreements ontology cache"]
fn official_agreements_closure_audit_is_complete() {
    let root = std::env::var("CTXQL_P5_7_AGREEMENTS_CACHE")
        .expect("CTXQL_P5_7_AGREEMENTS_CACHE must name the absolute external cache");
    let root = Path::new(&root);
    assert!(root.is_absolute());
    let manifest: OfficialClosure = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/p5_7/official-agreements-closure.json"
    ))
    .unwrap();
    assert_eq!(manifest.file_count, 20);
    assert_eq!(manifest.files.len(), 20);
    assert_eq!(manifest.total_authoritative_bytes, 401_555);
    assert_eq!(
        manifest.inventory_root,
        "sha256:f9a0255a5dbfbae1292807329d02c9d54898119f126ab82937b0abb9c75c1583"
    );

    let mut total = 0usize;
    let mut inventory_material = Vec::new();
    let mut conversions = Vec::new();
    for file in &manifest.files {
        let bytes = fs::read(root.join(&file.path)).unwrap();
        assert_eq!(bytes.len(), file.bytes, "{} byte count", file.path);
        assert_eq!(
            &ContentHash::of_bytes(&bytes).as_str()[7..],
            file.sha256,
            "{} hash",
            file.path
        );
        total += bytes.len();
        inventory_material.extend_from_slice(file.path.as_bytes());
        inventory_material.push(0);
        inventory_material.extend_from_slice(file.sha256.as_bytes());
        inventory_material.push(b'\n');
        let (release, base, graph) = official_identity(file);
        let conversion = convert_rdfxml(ConversionRequest {
            authoritative_bytes: &bytes,
            source_release_id: release,
            source_file_id: &file.path,
            base_iri: &base,
            graph_iri: &graph,
            limits: ConversionLimits {
                max_input_bytes: 128 * 1024 * 1024,
                max_input_triples: 1_000_000,
                max_output_bytes: 256 * 1024 * 1024,
                max_blank_nodes: 200_000,
                max_canonicalization_work: 50_000_000,
            },
        })
        .unwrap_or_else(|error| panic!("{}: {error}", file.path));
        let pin = ConversionPin::from_result(&conversion, &bytes).unwrap();
        conversions.push((graph, pin, conversion));
    }
    assert_eq!(total, manifest.total_authoritative_bytes);
    assert_eq!(
        ContentHash::of_bytes(&inventory_material).as_str(),
        manifest.inventory_root
    );

    let closure = build_audited_closure_from_conversions(conversions).unwrap();
    let audit = audit_ontology_closure(
        &closure,
        ConstructAuditLimits {
            max_bundle_quads: 500_000,
            max_source_occurrences: 1_000_000,
            max_structural_work: 50_000_000,
            max_issues: 500_000,
            max_serialized_output_bytes: 256 * 1024 * 1024,
            ..ConstructAuditLimits::default()
        },
    )
    .unwrap();
    assert!(audit.complete);
    assert!(audit.verify_integrity(&closure));
    assert_eq!(closure.bundle.len(), 3_632);
    assert_eq!(closure.occurrences.len(), 3_632);
    assert_eq!(
        closure.dependency_root.as_str(),
        "sha256:f752adac47d466247c5a18dd65f4234395aa891b7c30a0e597c17d4e1a9c6d73"
    );
    assert_eq!(
        closure.closure_root.as_str(),
        "sha256:c1026637354b4dea314083db4b843011ea045a4b75f0306a1199c794c4fbd2a8"
    );
    assert_eq!(
        closure.source_quad_root.as_str(),
        "sha256:a6a7a77a93bb7b0f669153ebf859764f866b45ef331aea638b95e92430e2e194"
    );
    assert_eq!(
        audit.source_entry_root.as_str(),
        "sha256:956dcb93507f05abf4bc2a6d88c87361d8bd56bf4f734bc8f4584120cb8adaa6"
    );
    assert_eq!(
        audit.bundle_classification_root.as_str(),
        "sha256:80d5f527ad61433dcc70f879721df7d1f0e8f6458b7a012889ed961839c2771b"
    );
    assert_eq!(
        audit.issue_root.as_str(),
        "sha256:759d90a06fd311d4cc0ad80b615edd733fdee33143daa8d32f8d53593795367b"
    );
    assert_eq!(
        audit.construct_audit_root.as_str(),
        "sha256:c1acad46309668d85044d8e015393c617c1c3e6a27aeeb592dc31d86a88c7c7e"
    );
    assert_eq!(
        audit.category_counts,
        BTreeMap::from([
            (ConstructDisposition::ReasonedCandidate, 3_012),
            (ConstructDisposition::DeclarationCandidate, 6),
            (ConstructDisposition::RetainedAnnotationCandidate, 515),
            (ConstructDisposition::Unsupported, 99),
        ])
    );
    assert!(closure.bundle.iter().any(|quad| {
        quad.subject.as_iri()
            == Some("https://spec.edmcouncil.org/fibo/ontology/FND/Agreements/Agreements/Agreement")
    }));
    for relationship in [
        "https://spec.edmcouncil.org/fibo/ontology/FND/Agreements/Agreements/hasObligation",
        "https://spec.edmcouncil.org/fibo/ontology/FND/Agreements/Agreements/isObligationOf",
    ] {
        assert!(closure
            .bundle
            .iter()
            .any(|quad| quad.subject.as_iri() == Some(relationship)));
    }

    if let Ok(path) = std::env::var("CTXQL_P5_7_AGREEMENTS_AUDIT_REPORT") {
        let category_counts = audit
            .category_counts
            .iter()
            .map(|(class, count)| (format!("{class:?}"), *count))
            .collect::<BTreeMap<_, _>>();
        let category_roots = audit
            .category_roots
            .iter()
            .map(|(class, root)| (format!("{class:?}"), root.as_str()))
            .collect::<BTreeMap<_, _>>();
        let report = json!({
            "schema": "ctxql.p5-7-official-construct-audit/v1",
            "scope": "FND/Agreements/Agreements",
            "file_count": manifest.file_count,
            "authoritative_bytes": total,
            "inventory_root": manifest.inventory_root,
            "complete": audit.complete,
            "accepted": audit.accepted,
            "bundle_quad_count": closure.bundle.len(),
            "source_occurrence_count": closure.occurrences.len(),
            "dependency_root": closure.dependency_root.as_str(),
            "closure_root": closure.closure_root.as_str(),
            "source_quad_root": closure.source_quad_root.as_str(),
            "source_entry_root": audit.source_entry_root.as_str(),
            "bundle_classification_root": audit.bundle_classification_root.as_str(),
            "issue_root": audit.issue_root.as_str(),
            "construct_audit_root": audit.construct_audit_root.as_str(),
            "category_counts": category_counts,
            "category_roots": category_roots,
            "official_bytes_in_report": false,
            "legal_clearance": false
        });
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("Agreements audit report path must be create-new");
        output
            .write_all((serde_json::to_string_pretty(&report).unwrap() + "\n").as_bytes())
            .unwrap();
    }

    println!(
        "P5_7_AGREEMENTS_AUDIT files={} bytes={} quads={} occurrences={} closure_root={} source_quad_root={} classification_root={} audit_root={} accepted={}",
        manifest.file_count,
        total,
        closure.bundle.len(),
        closure.occurrences.len(),
        closure.closure_root.as_str(),
        closure.source_quad_root.as_str(),
        audit.bundle_classification_root.as_str(),
        audit.construct_audit_root.as_str(),
        audit.accepted,
    );
}
