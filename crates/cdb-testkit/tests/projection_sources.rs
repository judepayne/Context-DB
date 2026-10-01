use cdb_core::{admission::*, contracts::*, evidence::*, id::*, snapshot::*, source::*, Limits};
use cdb_testkit::{projection::*, sources::*};
fn pin(n: &str) -> SnapshotRef {
    SnapshotRef::new(
        BackendId::new("backend").unwrap(),
        GraphPin::new(
            AuthorityId::new("authority").unwrap(),
            GraphId::new("graph").unwrap(),
            VersionId::new(n).unwrap(),
            ResourceId::new(format!("receipt-{n}")).unwrap(),
        ),
    )
}
fn cp(n: &str) -> ProjectionCheckpoint {
    ProjectionCheckpoint::new(
        pin(n),
        VersionId::new("ctxql-projection/v1").unwrap(),
        VersionId::new("generation").unwrap(),
        Iri::new("urn:algorithm").unwrap(),
    )
    .unwrap()
}
fn export(n: &str) -> CompleteExport {
    CompleteExport::collect(
        pin(n),
        ResourceId::new("export").unwrap(),
        vec![Page::new(vec![], pin(n), None, PageSize::new(1).unwrap()).unwrap()],
        10,
    )
    .unwrap()
}
async fn assert_exact(store: &impl ProjectionStore) {
    assert_eq!(
        store.open_view(&pin("a")).await.unwrap().identity(),
        &pin("a")
    );
    assert!(store.open_view(&pin("unknown")).await.is_err());
}
#[tokio::test]
async fn atomic_metadata_duplicate_and_exact_views() {
    let store = MemoryProjection::new(
        pin("a"),
        Iri::new("urn:algorithm").unwrap(),
        ProjectionOptions::default(),
    )
    .unwrap();
    store.build(&export("a"), &cp("a")).await.unwrap();
    let old = store.open_view(&pin("a")).await.unwrap();
    let batch = ChangeBatch::new(
        "ctxql-change/v1",
        pin("a"),
        pin("b"),
        vec![],
        Limits::default(),
    )
    .unwrap();
    store.set_write_fault(true);
    assert!(store.apply(&batch, &cp("b")).await.is_err());
    assert_eq!(store.checkpoint().await.unwrap(), Some(cp("a")));
    store.set_write_fault(false);
    store.apply(&batch, &cp("b")).await.unwrap();
    store.apply(&batch, &cp("b")).await.unwrap();
    assert_eq!(old.identity(), &pin("a"));
    assert_exact(&store).await;
    let gap = ChangeBatch::new(
        "ctxql-change/v1",
        pin("a"),
        pin("c"),
        vec![],
        Limits::default(),
    )
    .unwrap();
    assert!(store.apply(&gap, &cp("c")).await.is_err());
    store.set_read_fault(true);
    assert!(old
        .incident(
            &EntityId::new("absent").unwrap(),
            Direction::Both,
            PageSize::new(1).unwrap(),
            None
        )
        .is_err());
}
#[tokio::test]
async fn history_limit_is_atomic() {
    let store = MemoryProjection::new(
        pin("a"),
        Iri::new("urn:algorithm").unwrap(),
        ProjectionOptions {
            max_history: 1,
            ..ProjectionOptions::default()
        },
    )
    .unwrap();
    store.build(&export("a"), &cp("a")).await.unwrap();
    let b = ChangeBatch::new(
        "ctxql-change/v1",
        pin("a"),
        pin("b"),
        vec![],
        Limits::default(),
    )
    .unwrap();
    assert!(store.apply(&b, &cp("b")).await.is_err());
    assert_eq!(store.checkpoint().await.unwrap(), Some(cp("a")));
}
fn sources() -> ScriptedSources {
    ScriptedSources::new(
        vec![ImmutableSource::new(
            SourceId::new("s").unwrap(),
            "aéz".as_bytes().to_vec(),
        )],
        SourceOptions::default(),
    )
    .unwrap()
}
fn request() -> SourceReadRequest {
    SourceReadRequest {
        source_id: SourceId::new("s").unwrap(),
        version: ContentHash::of_bytes("aéz".as_bytes()),
        selector: EvidenceSelector::Span(Utf8Span::new(1, 3).unwrap()),
        max_bytes: 2,
    }
}
#[tokio::test]
async fn sources_bound_version_selector_issuer_and_budget() {
    let source = sources();
    let r = request();
    assert_eq!(source.read(&r).await.unwrap().bytes(), "é".as_bytes());
    let auth = source.authorize(&r).unwrap();
    assert!(sources().resolve(&auth, &r).await.is_err());
    let mut changed = r.clone();
    changed.selector = EvidenceSelector::WholeDocument;
    assert!(source.resolve(&auth, &changed).await.is_err());
    changed = r.clone();
    changed.max_bytes = 1;
    assert!(source.read(&changed).await.is_err());
    changed = r.clone();
    changed.version = ContentHash::of_bytes(b"other");
    assert!(source.read(&changed).await.is_err());
    source.set_read_fault(true);
    assert!(source.read(&r).await.is_err());
}
#[tokio::test]
async fn extractor_no_fallback_and_output_budget() {
    let source = sources().read(&request()).await.unwrap();
    let req = ExtractionRequest {
        source,
        extractor: cdb_core::artifact::ArtifactRef::new(
            Iri::new("urn:extractor").unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(b"script"),
        ),
        settings: cdb_core::CanonicalValue::Object(Default::default()),
        observed_at: cdb_core::Timestamp::parse("2020-01-01T00:00:00.000Z").unwrap(),
        max_candidates: 1,
    };
    let result = ExtractionResult::new(
        vec![],
        cdb_core::CanonicalValue::Object(Default::default()),
        1,
    )
    .unwrap();
    let extractor = ScriptedExtractor::new(
        vec![ExtractionScript {
            request: req.clone(),
            result,
        }],
        SourceOptions::default(),
    )
    .unwrap();
    assert!(extractor.extract(&req, Limits::default()).await.is_ok());
    let mut foreign = req.clone();
    foreign.observed_at = cdb_core::Timestamp::parse("2021-01-01T00:00:00.000Z").unwrap();
    assert!(extractor
        .extract(&foreign, Limits::default())
        .await
        .is_err());
    assert!(extractor
        .extract(&req, Limits::new(3, 64, 100, 10000, 100).unwrap())
        .await
        .is_err());
    assert!(extractor
        .extract(&req, Limits::new(100, 64, 100, 10000, 3).unwrap())
        .await
        .is_err());
    extractor.set_extract_fault(true);
    assert!(extractor.extract(&req, Limits::default()).await.is_err());
}

#[tokio::test]
async fn historical_cache_preserves_live_cursor() {
    let store = MemoryProjection::new(
        pin("a"),
        Iri::new("urn:algorithm").unwrap(),
        ProjectionOptions::default(),
    )
    .unwrap();
    store.build(&export("a"), &cp("a")).await.unwrap();
    let b = ChangeBatch::new(
        "ctxql-change/v1",
        pin("a"),
        pin("b"),
        vec![],
        Limits::default(),
    )
    .unwrap();
    store.apply(&b, &cp("b")).await.unwrap();
    store.build(&export("a"), &cp("a")).await.unwrap();
    let historical = ProjectionCheckpoint::new(
        pin("history"),
        VersionId::new("ctxql-projection/v1").unwrap(),
        VersionId::new("historical").unwrap(),
        Iri::new("urn:algorithm").unwrap(),
    )
    .unwrap();
    store.build(&export("history"), &historical).await.unwrap();
    store.build(&export("history"), &historical).await.unwrap();
    assert_eq!(store.checkpoint().await.unwrap(), Some(cp("b")));
}
#[tokio::test]
async fn retract_readd_same_identity_rejected() {
    let store = MemoryProjection::new(
        pin("a"),
        Iri::new("urn:algorithm").unwrap(),
        ProjectionOptions::default(),
    )
    .unwrap();
    let r = DependencyRecord::new(
        "ctxql-resource/v1",
        ResourceId::new("ontology").unwrap(),
        ResourceKind::Ontology,
        vec![Fact::new(
            Iri::new("urn:related").unwrap(),
            FactTerm::Reference(ResourceId::new("external").unwrap()),
        )],
    )
    .unwrap();
    let hash = ContentHash::of_bytes(&r.projection().canonical_bytes(Limits::default()).unwrap());
    let e = CompleteExport::collect(
        pin("a"),
        ResourceId::new("export").unwrap(),
        vec![Page::new(
            vec![ExportRecord::Resource(r.clone())],
            pin("a"),
            None,
            PageSize::new(1).unwrap(),
        )
        .unwrap()],
        10,
    )
    .unwrap();
    store.build(&e, &cp("a")).await.unwrap();
    let b = ChangeBatch::new(
        "ctxql-change/v1",
        pin("a"),
        pin("b"),
        vec![
            RecordChange::Resource(ResourceChange::RetractMutable {
                id: r.id().clone(),
                kind: r.kind(),
                previous: hash,
            }),
            RecordChange::Resource(ResourceChange::Add(r.clone())),
        ],
        Limits::default(),
    );
    assert!(b.is_err());
    assert_eq!(store.checkpoint().await.unwrap(), Some(cp("a")));
    assert_eq!(
        store
            .open_view(&pin("a"))
            .await
            .unwrap()
            .resource(r.id())
            .unwrap(),
        Some(r)
    );
}

#[tokio::test]
async fn retained_artifact_and_source_versions() {
    use cdb_core::artifact::*;
    let store = MemoryProjection::new(
        pin("a"),
        Iri::new("urn:algorithm").unwrap(),
        ProjectionOptions::default(),
    )
    .unwrap();
    let records: Vec<_> = ["1", "2"]
        .into_iter()
        .map(|v| {
            ExportRecord::Artifact(
                PublishedArtifact::new(
                    ArtifactRef::new(
                        Iri::new("urn:artifact").unwrap(),
                        VersionId::new(v).unwrap(),
                        ContentHash::of_bytes(v.as_bytes()),
                    ),
                    v.as_bytes().to_vec(),
                    Limits::default(),
                )
                .unwrap(),
            )
        })
        .collect();
    let e = CompleteExport::collect(
        pin("a"),
        ResourceId::new("export").unwrap(),
        vec![Page::new(records, pin("a"), None, PageSize::new(2).unwrap()).unwrap()],
        10,
    )
    .unwrap();
    store.build(&e, &cp("a")).await.unwrap();
    let id = SourceId::new("s").unwrap();
    let sources = ScriptedSources::new(
        vec![
            ImmutableSource::new(id.clone(), b"abc".to_vec()),
            ImmutableSource::new(id.clone(), b"def".to_vec()),
        ],
        SourceOptions::default(),
    )
    .unwrap();
    for text in [b"abc", b"def"] {
        let r = SourceReadRequest {
            source_id: id.clone(),
            version: ContentHash::of_bytes(text),
            selector: EvidenceSelector::WholeDocument,
            max_bytes: 3,
        };
        assert_eq!(sources.read(&r).await.unwrap().bytes(), text);
        let auth = sources.authorize(&r).unwrap();
        let mut span = r.clone();
        span.selector = EvidenceSelector::Span(Utf8Span::new(0, 1).unwrap());
        assert!(sources.resolve(&auth, &span).await.is_err());
    }
}
