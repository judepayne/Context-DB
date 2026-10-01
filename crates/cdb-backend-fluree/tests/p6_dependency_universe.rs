use cdb_backend_fluree::{
    ontology_conversion::{convert_rdfxml, ConversionLimits, ConversionRequest},
    ontology_dependency_universe::{
        ConversionPin, OntologyDependencyUniverse, OntologyOwnership, UniverseErrorKind,
        UniverseLimits, ONTOLOGY_DEPENDENCY_UNIVERSE_INVALID,
    },
    ontology_release::{
        ArtifactClassification, ArtifactRole, CompleteInventory, InventoryEntry,
        RelativeSourcePath, ReleaseEvidence, ReleaseForm, SourceArtifactPin, SourceReleaseManifest,
    },
};
use cdb_core::id::ContentHash;

fn path(v: &str) -> RelativeSourcePath {
    RelativeSourcePath::new(v).unwrap()
}
fn class(role: ArtifactRole, media: &str) -> ArtifactClassification {
    ArtifactClassification::new(role, media).unwrap()
}
fn rdf(ontology: &str, imports: &[&str]) -> Vec<u8> {
    let imports = imports
        .iter()
        .map(|v| format!(r#"<owl:imports rdf:resource="{v}"/>"#))
        .collect::<String>();
    format!(r#"<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:owl="http://www.w3.org/2002/07/owl#"><owl:Ontology rdf:about="{ontology}"><owl:versionIRI rdf:resource="{ontology}/2026"/>{imports}</owl:Ontology></rdf:RDF>"#).into_bytes()
}
fn release(
    product: &str,
    version: &str,
    files: &[(&str, &[u8], ArtifactRole)],
) -> SourceReleaseManifest {
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
    let mut artifacts = vec![];
    for (file, bytes, role) in files {
        let media = if *role == ArtifactRole::OntologyRdf {
            "application/rdf+xml"
        } else {
            "text/plain"
        };
        let classification = class(*role, media);
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
                format!("https://example.org/spec/{version}/{file}.rdf"),
                version,
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
        version,
        ReleaseForm::SyntheticArtifacts,
        Some(version.into()),
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
        imports.iter().map(|v| (*v).into()).collect(),
    )
    .unwrap()
}
fn seal(
    releases: Vec<SourceReleaseManifest>,
    owners: Vec<OntologyOwnership>,
) -> Result<
    OntologyDependencyUniverse,
    cdb_backend_fluree::ontology_dependency_universe::UniverseError,
> {
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
fn role_authoritative_cross_release_closure_is_exact() {
    let a_bytes = rdf("https://spec.example/A", &["https://spec.example/B"]);
    let b_bytes = rdf("https://spec.example/B", &[]);
    let a = release(
        "A",
        "1.0",
        &[("deceptive.bin", &a_bytes, ArtifactRole::OntologyRdf)],
    );
    let b = release(
        "B",
        "1.0",
        &[("also.data", &b_bytes, ArtifactRole::OntologyRdf)],
    );
    let universe = seal(
        vec![a.clone(), b.clone()],
        vec![
            owner(
                &a,
                "https://spec.example/A",
                "deceptive.bin",
                &a_bytes,
                &["https://spec.example/B"],
            ),
            owner(&b, "https://spec.example/B", "also.data", &b_bytes, &[]),
        ],
    )
    .unwrap();
    assert_eq!(
        universe
            .transitive_closure(&["https://spec.example/A".into()])
            .unwrap(),
        vec!["https://spec.example/B", "https://spec.example/A"]
    );
}

#[test]
fn deceptive_rdf_extension_cannot_create_ownership_obligation() {
    let ontology = rdf("https://spec.example/A", &[]);
    let release = release(
        "A",
        "1.0",
        &[
            ("README.owl", b"not rdf", ArtifactRole::Other),
            ("ontology.data", &ontology, ArtifactRole::OntologyRdf),
        ],
    );
    seal(
        vec![release.clone()],
        vec![owner(
            &release,
            "https://spec.example/A",
            "ontology.data",
            &ontology,
            &[],
        )],
    )
    .unwrap();
}

#[test]
fn every_ontology_role_requires_exactly_one_owner_and_non_ontology_cannot_own() {
    let first = rdf("https://spec.example/First", &[]);
    let second = rdf("https://spec.example/Second", &[]);
    let source_release = release(
        "X",
        "1.0",
        &[
            ("first.data", &first, ArtifactRole::OntologyRdf),
            ("second.data", &second, ArtifactRole::OntologyRdf),
        ],
    );
    assert_eq!(
        seal(
            vec![source_release.clone()],
            vec![owner(
                &source_release,
                "https://spec.example/First",
                "first.data",
                &first,
                &[]
            )]
        )
        .unwrap_err()
        .kind(),
        UniverseErrorKind::MissingArtifact
    );

    let only_other = release("Y", "1.0", &[("looks.rdf", &first, ArtifactRole::Other)]);
    let fake_owner = owner(
        &only_other,
        "https://spec.example/First",
        "looks.rdf",
        &first,
        &[],
    );
    assert_eq!(
        seal(vec![only_other], vec![fake_owner]).unwrap_err().kind(),
        UniverseErrorKind::MissingArtifact
    );
}

#[test]
fn substitution_missing_import_cycle_and_duplicate_fail_closed() {
    let official = rdf("https://spec.example/A", &[]);
    let substituted = rdf("https://spec.example/Sub", &[]);
    let release_a = release("A", "1.0", &[("a", &official, ArtifactRole::OntologyRdf)]);
    let error = seal(
        vec![release_a.clone()],
        vec![owner(
            &release_a,
            "https://spec.example/Sub",
            "a",
            &substituted,
            &[],
        )],
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), ONTOLOGY_DEPENDENCY_UNIVERSE_INVALID);
    assert_eq!(error.kind(), UniverseErrorKind::HashMismatch);

    let missing_bytes = rdf("https://spec.example/A", &["https://spec.example/Missing"]);
    let missing_release = release(
        "M",
        "1.0",
        &[("m", &missing_bytes, ArtifactRole::OntologyRdf)],
    );
    assert_eq!(
        seal(
            vec![missing_release.clone()],
            vec![owner(
                &missing_release,
                "https://spec.example/A",
                "m",
                &missing_bytes,
                &["https://spec.example/Missing"]
            )]
        )
        .unwrap_err()
        .kind(),
        UniverseErrorKind::UnresolvedImport
    );

    let a_bytes = rdf("https://spec.example/A", &["https://spec.example/B"]);
    let b_bytes = rdf("https://spec.example/B", &["https://spec.example/A"]);
    let a = release("A", "1.0", &[("a", &a_bytes, ArtifactRole::OntologyRdf)]);
    let b = release("B", "1.0", &[("b", &b_bytes, ArtifactRole::OntologyRdf)]);
    assert_eq!(
        seal(
            vec![a.clone(), b.clone()],
            vec![
                owner(
                    &a,
                    "https://spec.example/A",
                    "a",
                    &a_bytes,
                    &["https://spec.example/B"]
                ),
                owner(
                    &b,
                    "https://spec.example/B",
                    "b",
                    &b_bytes,
                    &["https://spec.example/A"]
                )
            ]
        )
        .unwrap_err()
        .kind(),
        UniverseErrorKind::ImportCycle
    );

    let duplicate = release("D", "1.0", &[("d", &official, ArtifactRole::OntologyRdf)]);
    let one = owner(&duplicate, "https://spec.example/A", "d", &official, &[]);
    assert_eq!(
        seal(vec![duplicate], vec![one.clone(), one])
            .unwrap_err()
            .kind(),
        UniverseErrorKind::DuplicateOwnership
    );
}

#[test]
fn roots_are_independent_of_input_order() {
    let a_bytes = rdf("https://spec.example/A", &["https://spec.example/B"]);
    let b_bytes = rdf("https://spec.example/B", &[]);
    let a = release("A", "1.0", &[("a", &a_bytes, ArtifactRole::OntologyRdf)]);
    let b = release("B", "1.0", &[("b", &b_bytes, ArtifactRole::OntologyRdf)]);
    let ao = owner(
        &a,
        "https://spec.example/A",
        "a",
        &a_bytes,
        &["https://spec.example/B"],
    );
    let bo = owner(&b, "https://spec.example/B", "b", &b_bytes, &[]);
    let first = seal(vec![a.clone(), b.clone()], vec![ao.clone(), bo.clone()]).unwrap();
    let second = seal(vec![b, a], vec![bo, ao]).unwrap();
    assert_eq!(first.root(), second.root());
}
