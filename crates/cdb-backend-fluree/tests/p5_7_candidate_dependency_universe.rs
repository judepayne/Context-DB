use cdb_backend_fluree::{
    ontology_conversion::{convert_rdfxml, ConversionLimits, ConversionRequest},
    ontology_dependency_universe::{
        CandidateScopedDependencyUniverse, ConversionPin, OntologyDependencyUniverse,
        OntologyOwnership, UniverseError, UniverseErrorKind, UniverseLimits,
    },
    ontology_release::{
        ArtifactClassification, ArtifactRole, CompleteInventory, InventoryEntry,
        RelativeSourcePath, ReleaseEvidence, ReleaseForm, SourceArtifactPin, SourceReleaseManifest,
    },
};
use cdb_core::id::ContentHash;

fn path(value: &str) -> RelativeSourcePath {
    RelativeSourcePath::new(value).unwrap()
}

fn class(role: ArtifactRole, media_type: &str) -> ArtifactClassification {
    ArtifactClassification::new(role, media_type).unwrap()
}

fn rdf(ontology: &str, imports: &[&str]) -> Vec<u8> {
    let imports = imports
        .iter()
        .map(|value| format!(r#"<owl:imports rdf:resource="{value}"/>"#))
        .collect::<String>();
    format!(
        r#"<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:owl="http://www.w3.org/2002/07/owl#"><owl:Ontology rdf:about="{ontology}"><owl:versionIRI rdf:resource="{ontology}/2026"/>{imports}</owl:Ontology></rdf:RDF>"#
    )
    .into_bytes()
}

fn release(product: &str, files: &[(&str, &[u8], ArtifactRole)]) -> SourceReleaseManifest {
    let license = format!("{product} license").into_bytes();
    let notice = format!("{product} notice").into_bytes();
    let mut entries = vec![
        InventoryEntry::new(
            path("LICENSE"),
            ContentHash::of_bytes(&license),
            license.len() as u64,
            class(ArtifactRole::License, "text/plain"),
        )
        .unwrap(),
        InventoryEntry::new(
            path("NOTICE"),
            ContentHash::of_bytes(&notice),
            notice.len() as u64,
            class(ArtifactRole::Notice, "text/plain"),
        )
        .unwrap(),
    ];
    let mut artifacts = Vec::new();
    for (file, bytes, role) in files {
        let media_type = if *role == ArtifactRole::OntologyRdf {
            "application/rdf+xml"
        } else {
            "text/plain"
        };
        let classification = class(*role, media_type);
        entries.push(
            InventoryEntry::new(
                path(file),
                ContentHash::of_bytes(bytes),
                bytes.len() as u64,
                classification.clone(),
            )
            .unwrap(),
        );
        artifacts.push(
            SourceArtifactPin::new(
                path(file),
                format!("https://example.org/{product}/1.0/{file}"),
                "1.0",
                ContentHash::of_bytes(bytes),
                bytes.len() as u64,
                classification,
            )
            .unwrap(),
        );
    }
    SourceReleaseManifest::new(
        "Official Publisher",
        product,
        "1.0",
        ReleaseForm::SyntheticArtifacts,
        Some("1.0".into()),
        None,
        None,
        None,
        None,
        artifacts,
        vec![
            ReleaseEvidence::license(path("LICENSE"), ContentHash::of_bytes(&license)),
            ReleaseEvidence::notice(path("NOTICE"), ContentHash::of_bytes(&notice)),
        ],
        CompleteInventory::new(entries).unwrap(),
        Some("limits/v1".into()),
        "immutable",
    )
    .unwrap()
}

fn owner(
    release: &SourceReleaseManifest,
    ontology: &str,
    file: &str,
    bytes: &[u8],
    imports: &[&str],
) -> OntologyOwnership {
    let graph = format!("urn:ctxql:graph:{}", ontology.rsplit('/').next().unwrap());
    let result = convert_rdfxml(ConversionRequest {
        authoritative_bytes: bytes,
        source_release_id: release.id().as_str(),
        source_file_id: file,
        base_iri: ontology,
        graph_iri: &graph,
        limits: ConversionLimits::default(),
    })
    .unwrap();
    OntologyOwnership::new(
        ontology,
        format!("{ontology}/2026"),
        release.id().clone(),
        path(file),
        ContentHash::of_bytes(bytes),
        "application/rdf+xml",
        ConversionPin::from_result(&result, bytes).unwrap(),
        graph,
        imports.iter().map(|value| (*value).into()).collect(),
    )
    .unwrap()
}

fn seal_v2(
    releases: Vec<SourceReleaseManifest>,
    owners: Vec<OntologyOwnership>,
) -> Result<CandidateScopedDependencyUniverse, UniverseError> {
    CandidateScopedDependencyUniverse::seal(
        releases,
        owners,
        vec![],
        "offline-exact/v1",
        "limits/v1",
        "analyzer/v1",
        "candidate-resolver/v2",
        "kosaraju-iterative/v1",
        UniverseLimits::default(),
    )
}

fn seal_v1(
    releases: Vec<SourceReleaseManifest>,
    owners: Vec<OntologyOwnership>,
) -> Result<OntologyDependencyUniverse, UniverseError> {
    OntologyDependencyUniverse::seal(
        releases,
        owners,
        vec![],
        "offline-exact/v1",
        "limits/v1",
        "analyzer/v1",
        "resolver/v1",
        UniverseLimits::default(),
    )
}

#[test]
fn unselected_cycle_and_unresolved_edge_do_not_block_an_acyclic_candidate() {
    let good_bytes = rdf("https://spec.example/Good", &[]);
    let cycle_a_bytes = rdf(
        "https://spec.example/CycleA",
        &["https://spec.example/CycleB"],
    );
    let cycle_b_bytes = rdf(
        "https://spec.example/CycleB",
        &["https://spec.example/CycleA"],
    );
    let unresolved_bytes = rdf(
        "https://spec.example/Unresolved",
        &["https://spec.example/Missing"],
    );
    let source = release(
        "All",
        &[
            ("good.rdf", &good_bytes, ArtifactRole::OntologyRdf),
            ("cycle-a.rdf", &cycle_a_bytes, ArtifactRole::OntologyRdf),
            ("cycle-b.rdf", &cycle_b_bytes, ArtifactRole::OntologyRdf),
            (
                "unresolved.rdf",
                &unresolved_bytes,
                ArtifactRole::OntologyRdf,
            ),
        ],
    );
    let universe = seal_v2(
        vec![source.clone()],
        vec![
            owner(
                &source,
                "https://spec.example/Good",
                "good.rdf",
                &good_bytes,
                &[],
            ),
            owner(
                &source,
                "https://spec.example/CycleA",
                "cycle-a.rdf",
                &cycle_a_bytes,
                &["https://spec.example/CycleB"],
            ),
            owner(
                &source,
                "https://spec.example/CycleB",
                "cycle-b.rdf",
                &cycle_b_bytes,
                &["https://spec.example/CycleA"],
            ),
            owner(
                &source,
                "https://spec.example/Unresolved",
                "unresolved.rdf",
                &unresolved_bytes,
                &["https://spec.example/Missing"],
            ),
        ],
    )
    .unwrap();

    assert_eq!(
        universe
            .transitive_closure(&["https://spec.example/Good".into()])
            .unwrap(),
        vec!["https://spec.example/Good"]
    );
    assert_eq!(universe.unresolved_imports().len(), 1);
    assert!(universe.strongly_connected_components().contains(&vec![
        "https://spec.example/CycleA".into(),
        "https://spec.example/CycleB".into(),
    ]));
}

#[test]
fn selected_cycle_self_loop_and_unresolved_import_fail_closed() {
    let cycle_a_bytes = rdf(
        "https://spec.example/CycleA",
        &["https://spec.example/CycleB"],
    );
    let cycle_b_bytes = rdf(
        "https://spec.example/CycleB",
        &["https://spec.example/CycleA"],
    );
    let self_bytes = rdf("https://spec.example/Self", &["https://spec.example/Self"]);
    let unresolved_bytes = rdf(
        "https://spec.example/Unresolved",
        &["https://spec.example/Missing"],
    );
    let source = release(
        "Bad",
        &[
            ("cycle-a.rdf", &cycle_a_bytes, ArtifactRole::OntologyRdf),
            ("cycle-b.rdf", &cycle_b_bytes, ArtifactRole::OntologyRdf),
            ("self.rdf", &self_bytes, ArtifactRole::OntologyRdf),
            (
                "unresolved.rdf",
                &unresolved_bytes,
                ArtifactRole::OntologyRdf,
            ),
        ],
    );
    let owners = vec![
        owner(
            &source,
            "https://spec.example/CycleA",
            "cycle-a.rdf",
            &cycle_a_bytes,
            &["https://spec.example/CycleB"],
        ),
        owner(
            &source,
            "https://spec.example/CycleB",
            "cycle-b.rdf",
            &cycle_b_bytes,
            &["https://spec.example/CycleA"],
        ),
        owner(
            &source,
            "https://spec.example/Self",
            "self.rdf",
            &self_bytes,
            &["https://spec.example/Self"],
        ),
        owner(
            &source,
            "https://spec.example/Unresolved",
            "unresolved.rdf",
            &unresolved_bytes,
            &["https://spec.example/Missing"],
        ),
    ];
    let universe = seal_v2(vec![source], owners).unwrap();
    assert_eq!(
        universe
            .transitive_closure(&["https://spec.example/CycleA".into()])
            .unwrap_err()
            .kind(),
        UniverseErrorKind::ImportCycle
    );
    assert_eq!(
        universe
            .transitive_closure(&["https://spec.example/Self".into()])
            .unwrap_err()
            .kind(),
        UniverseErrorKind::ImportCycle
    );
    assert_eq!(
        universe
            .transitive_closure(&["https://spec.example/Unresolved".into()])
            .unwrap_err()
            .kind(),
        UniverseErrorKind::UnresolvedImport
    );
    assert_eq!(
        universe
            .transitive_closure(&["https://spec.example/Outside".into()])
            .unwrap_err()
            .kind(),
        UniverseErrorKind::OutOfUniverseImport
    );
}

#[test]
fn v2_roots_and_closure_are_permutation_invariant() {
    let a_bytes = rdf("https://spec.example/A", &["https://spec.example/B"]);
    let b_bytes = rdf("https://spec.example/B", &[]);
    let a = release("A", &[("a.rdf", &a_bytes, ArtifactRole::OntologyRdf)]);
    let b = release("B", &[("b.rdf", &b_bytes, ArtifactRole::OntologyRdf)]);
    let ao = owner(
        &a,
        "https://spec.example/A",
        "a.rdf",
        &a_bytes,
        &["https://spec.example/B"],
    );
    let bo = owner(&b, "https://spec.example/B", "b.rdf", &b_bytes, &[]);
    let first = seal_v2(vec![a.clone(), b.clone()], vec![ao.clone(), bo.clone()]).unwrap();
    let second = seal_v2(vec![b, a], vec![bo, ao]).unwrap();
    assert_eq!(first.root(), second.root());
    assert_eq!(
        first.canonical_json().unwrap(),
        second.canonical_json().unwrap()
    );
    assert_eq!(
        first
            .transitive_closure(&["https://spec.example/A".into()])
            .unwrap(),
        vec!["https://spec.example/B", "https://spec.example/A"]
    );
}

#[test]
fn v1_still_rejects_release_wide_cycle_and_unresolved_import() {
    let a_bytes = rdf("https://spec.example/A", &["https://spec.example/B"]);
    let b_bytes = rdf("https://spec.example/B", &["https://spec.example/A"]);
    let cycle = release(
        "Cycle",
        &[
            ("a.rdf", &a_bytes, ArtifactRole::OntologyRdf),
            ("b.rdf", &b_bytes, ArtifactRole::OntologyRdf),
        ],
    );
    assert_eq!(
        seal_v1(
            vec![cycle.clone()],
            vec![
                owner(
                    &cycle,
                    "https://spec.example/A",
                    "a.rdf",
                    &a_bytes,
                    &["https://spec.example/B"],
                ),
                owner(
                    &cycle,
                    "https://spec.example/B",
                    "b.rdf",
                    &b_bytes,
                    &["https://spec.example/A"],
                ),
            ],
        )
        .unwrap_err()
        .kind(),
        UniverseErrorKind::ImportCycle
    );

    let unresolved_bytes = rdf("https://spec.example/U", &["https://spec.example/Missing"]);
    let unresolved = release(
        "Unresolved",
        &[("u.rdf", &unresolved_bytes, ArtifactRole::OntologyRdf)],
    );
    assert_eq!(
        seal_v1(
            vec![unresolved.clone()],
            vec![owner(
                &unresolved,
                "https://spec.example/U",
                "u.rdf",
                &unresolved_bytes,
                &["https://spec.example/Missing"],
            )],
        )
        .unwrap_err()
        .kind(),
        UniverseErrorKind::UnresolvedImport
    );
}

#[test]
fn substituted_or_ambiguous_ownership_cannot_enter_v2() {
    let official = rdf("https://spec.example/A", &[]);
    let substituted = rdf("https://spec.example/Substituted", &[]);
    let source = release(
        "Ownership",
        &[("a.rdf", &official, ArtifactRole::OntologyRdf)],
    );
    assert_eq!(
        seal_v2(
            vec![source.clone()],
            vec![owner(
                &source,
                "https://spec.example/Substituted",
                "a.rdf",
                &substituted,
                &[],
            )],
        )
        .unwrap_err()
        .kind(),
        UniverseErrorKind::HashMismatch
    );

    let exact = owner(&source, "https://spec.example/A", "a.rdf", &official, &[]);
    assert_eq!(
        seal_v2(vec![source], vec![exact.clone(), exact])
            .unwrap_err()
            .kind(),
        UniverseErrorKind::DuplicateOwnership
    );
}

#[test]
fn selected_depth_limit_is_enforced() {
    let a_bytes = rdf("https://spec.example/A", &["https://spec.example/B"]);
    let b_bytes = rdf("https://spec.example/B", &[]);
    let source = release(
        "Depth",
        &[
            ("a.rdf", &a_bytes, ArtifactRole::OntologyRdf),
            ("b.rdf", &b_bytes, ArtifactRole::OntologyRdf),
        ],
    );
    let universe = CandidateScopedDependencyUniverse::seal(
        vec![source.clone()],
        vec![
            owner(
                &source,
                "https://spec.example/A",
                "a.rdf",
                &a_bytes,
                &["https://spec.example/B"],
            ),
            owner(&source, "https://spec.example/B", "b.rdf", &b_bytes, &[]),
        ],
        vec![],
        "offline-exact/v1",
        "limits/depth-one",
        "analyzer/v1",
        "candidate-resolver/v2",
        "kosaraju-iterative/v1",
        UniverseLimits {
            max_closure_depth: 1,
            ..UniverseLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        universe
            .transitive_closure(&["https://spec.example/A".into()])
            .unwrap_err()
            .kind(),
        UniverseErrorKind::LimitExceeded
    );
}
