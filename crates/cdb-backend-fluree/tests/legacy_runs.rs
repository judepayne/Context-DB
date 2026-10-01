use cdb_backend_fluree::{AuthorityOptions, FlureeBackend};
use cdb_core::{
    artifact::*, contracts::ArtifactRepository, id::*, replay::*, snapshot::SnapshotRef, Limits,
};
fn run(snapshot: SnapshotRef, functions: bool) -> ExecutionRun {
    let l = Limits::default();
    let bytes = b" { \"value\" : 1 } \n".to_vec();
    let reference = ArtifactRef::new(
        Iri::new("https://example.org/function").unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(&bytes),
    );
    let artifact = PublishedArtifact::new(reference.clone(), bytes, l).unwrap();
    let manifest =
        FunctionManifest::from_published(ResourceId::new("function").unwrap(), &artifact, l)
            .unwrap();
    assert_ne!(
        manifest.hash(),
        &ContentHash::of_bytes(&manifest.content().canonical_bytes(l).unwrap())
    );
    let selector = ResourceId::new("selector").unwrap();
    let footprint = ReadFootprint::new(
        "ctxql-read-footprint/v1",
        snapshot.clone(),
        vec![
            ReadDependency::Claim(ClaimId::new("claim").unwrap()),
            ReadDependency::Lifecycle(ClaimId::new("event").unwrap()),
            ReadDependency::Resource(ResourceId::new("resource").unwrap()),
            ReadDependency::Fact {
                resource: ResourceId::new("resource").unwrap(),
                predicate: Iri::new("https://example.org/p").unwrap(),
            },
            ReadDependency::NegativeLookup {
                descriptor: ResourceId::new("scope").unwrap(),
            },
            ReadDependency::Artifact(reference.clone()),
            ReadDependency::SourceSelector {
                descriptor: selector.clone(),
                source: SourceId::new("source").unwrap(),
                version: ContentHash::of_bytes(b"source"),
            },
            ReadDependency::OrderingDescriptor(ResourceId::new("order").unwrap()),
        ],
        vec![selector],
    )
    .unwrap();
    ExecutionRun::new(ExecutionRunInput {
        schema: "ctxql-execution-run/v1".into(),
        id: RunId::new("legacy").unwrap(),
        query: reference.clone(),
        profile: Some(reference.clone()),
        config: reference,
        engine: EngineIdentity::new(
            Iri::new("https://example.org/engine").unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(b"build"),
        ),
        plan_hash: ContentHash::of_bytes(b"plan"),
        response_hash: ContentHash::of_bytes(b"response"),
        snapshot,
        as_of: cdb_core::Timestamp::parse("2024-01-01T00:00:00Z").unwrap(),
        landings: vec![],
        functions: if functions {
            vec![FunctionCallSummary::new(
                manifest,
                vec![ContentHash::of_bytes(b"in")],
                vec![ContentHash::of_bytes(b"out")],
            )
            .unwrap()]
        } else {
            vec![]
        },
        footprint,
    })
    .unwrap()
}

fn options(path: &std::path::Path) -> AuthorityOptions {
    AuthorityOptions::new(
        path.join("db"),
        "legacy:main".into(),
        BackendId::new("fluree").unwrap(),
        AuthorityId::new("owner").unwrap(),
        GraphId::new("graph").unwrap(),
    )
}
#[tokio::test]
async fn legacy_repository_reopen_idempotency_and_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let b = FlureeBackend::create(options(dir.path())).await.unwrap();
    let snapshot = b.head().await.unwrap();
    let original = run(snapshot, true);
    assert!(b.run(original.id()).await.unwrap().is_none());
    b.record_run(&original).await.unwrap();
    let committed = b.head().await.unwrap();
    assert_eq!(b.run(original.id()).await.unwrap(), Some(original.clone()));
    b.record_run(&original).await.unwrap();
    assert_eq!(b.head().await.unwrap(), committed);
    drop(b);
    let b = FlureeBackend::open(options(dir.path())).await.unwrap();
    assert_eq!(b.run(original.id()).await.unwrap(), Some(original.clone()));
    b.record_run(&original).await.unwrap();
    assert_eq!(b.head().await.unwrap(), committed);
    let changed = run(original.snapshot().clone(), false);
    assert_eq!(
        b.record_run(&changed).await.unwrap_err().kind,
        cdb_core::ErrorKind::Conflict
    );
    assert_eq!(b.head().await.unwrap(), committed);
    assert_eq!(b.run(original.id()).await.unwrap(), Some(original));
}
