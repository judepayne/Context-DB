//! Current native selector grants precede the real private content-addressed reader.
#[allow(dead_code)]
mod common_p3;
use cdb_core::{
    admission::ExportRecord,
    contracts::{AuthorizedSelectorResolver, SourceReader},
    evidence::{EvidenceSelector, Utf8Span},
    id::*,
    policy::PolicySet,
    source::SourceReadRequest,
    CanonicalValue as V, ErrorKind, Limits,
};
use cdb_service::sources::{selector_records, AuthorizedSources, SourceStore};
use cdb_testkit::reference_fixture::FixtureBuilder;
use common_p3::{reader_policy, NativeFixture};
use std::sync::Arc;
const TEXT: &str = "Aé🙂\n漢Z";
fn request(start: usize, end: usize) -> SourceReadRequest {
    SourceReadRequest {
        source_id: SourceId::new("text-example").unwrap(),
        version: ContentHash::of_bytes(TEXT.as_bytes()),
        selector: EvidenceSelector::Span(Utf8Span::new(start, end).unwrap()),
        max_bytes: 32,
    }
}
fn record_id(record: &ExportRecord) -> ResourceId {
    let ExportRecord::Resource(record) = record else {
        unreachable!()
    };
    record.id().clone()
}
fn passed(n: usize) {
    println!("P4_CASE {{\"id\":\"P4-S{n:03}\",\"outcome\":\"passed\"}}");
}
async fn fixture(requests: &[(&SourceReadRequest, &[u8])]) -> NativeFixture {
    let mut builder = FixtureBuilder::new();
    for (request, bytes) in requests {
        for record in selector_records(request, &ContentHash::of_bytes(bytes)).unwrap() {
            let ExportRecord::Resource(record) = record else {
                unreachable!()
            };
            builder.resource(record);
        }
    }
    NativeFixture::new(builder, reader_policy(), 128).await
}
fn store() -> (tempfile::TempDir, Arc<SourceStore>) {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(SourceStore::open(root.path().canonicalize().unwrap(), 1024).unwrap());
    store.put(TEXT.as_bytes()).unwrap();
    (root, store)
}
async fn guard(
    f: &NativeFixture,
    store: Arc<SourceStore>,
) -> AuthorizedSources<cdb_backend_fluree::FlureeBackend, cdb_backend_fluree::FlureeBackend> {
    let guard = AuthorizedSources::new(
        f.backend.clone(),
        f.backend.clone(),
        Arc::new(f.principal.clone()),
        store,
    );
    guard
        .bind_snapshot(&f.backend.head().await.unwrap())
        .unwrap();
    guard
}
async fn deny(f: &NativeFixture, id: &ResourceId, key: &str) {
    let mut state = reader_policy();
    state.classes.insert(
        id.clone(),
        [Iri::new("https://fixture.example/Secret").unwrap()].into(),
    );
    let mut value = state.policy.projection().as_object().unwrap().clone();
    let mut rules = value["policies"].as_array().unwrap().to_vec();
    rules.push(V::parse(br#"{"@id":"https://fixture.example/source-deny","@type":["https://ns.flur.ee/db#AccessPolicy","https://fixture.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":false,"https://ns.flur.ee/db#onClass":"https://fixture.example/Secret"}"#, Limits::default()).unwrap());
    value.insert("policies".into(), V::Array(rules));
    state.policy = PolicySet::from_value(&V::Object(value)).unwrap();
    f.advance();
    f.backend
        .set_policy_state(&IdempotencyKey::new(key).unwrap(), &state)
        .await
        .unwrap();
}
#[tokio::test]
async fn exact_unicode_empty_and_separate_whole_document_grants() {
    let span = request(3, 11);
    let mut empty = request(3, 3);
    empty.max_bytes = 0;
    let whole = SourceReadRequest {
        selector: EvidenceSelector::WholeDocument,
        ..span.clone()
    };
    let f = fixture(&[
        (&span, "🙂\n漢".as_bytes()),
        (&empty, b""),
        (&whole, TEXT.as_bytes()),
    ])
    .await;
    let (_root, store) = store();
    let reader = guard(&f, store.clone()).await;
    assert_eq!(
        reader.read(&span).await.unwrap().bytes(),
        "🙂\n漢".as_bytes()
    );
    assert!(reader.read(&empty).await.unwrap().bytes().is_empty());
    assert_eq!(reader.read(&whole).await.unwrap().bytes(), TEXT.as_bytes());
    assert_eq!(reader.footprint().unwrap().len(), 10);
    passed(1);
    let grant = reader.authorize(&span).await.unwrap();
    let before = store.reads_started();
    assert_eq!(
        reader.resolve(&grant, &whole).await.err().unwrap().kind,
        ErrorKind::Denied
    );
    let foreign = guard(&f, store.clone()).await;
    assert_eq!(
        foreign.resolve(&grant, &span).await.err().unwrap().kind,
        ErrorKind::Denied
    );
    assert_eq!(store.reads_started(), before);
    passed(2);
    let whole_id = record_id(&selector_records(&whole, &whole.version).unwrap()[2]);
    deny(&f, &whole_id, "deny-document").await;
    assert_eq!(
        reader.read(&whole).await.err().unwrap().kind,
        ErrorKind::Denied
    );
    assert_eq!(
        reader.read(&span).await.unwrap().bytes(),
        "🙂\n漢".as_bytes()
    );
    passed(3);
    drop(reader);
    drop(foreign);
    f.shutdown().await;
}
#[tokio::test]
async fn every_descriptor_and_revoked_capability_fail_before_reader() {
    let request = request(3, 11);
    let f = fixture(&[(&request, "🙂\n漢".as_bytes())]).await;
    let (_root, store) = store();
    let reader = guard(&f, store.clone()).await;
    let records = selector_records(&request, &ContentHash::of_bytes("🙂\n漢".as_bytes())).unwrap();
    for (n, record) in records.iter().enumerate() {
        f.advance();
        f.backend
            .set_policy_state(
                &IdempotencyKey::new(format!("reset-{n}")).unwrap(),
                &reader_policy(),
            )
            .await
            .unwrap();
        let grant = reader.authorize(&request).await.unwrap();
        deny(&f, &record_id(record), &format!("deny-{n}")).await;
        let before = store.reads_started();
        assert_eq!(
            reader.resolve(&grant, &request).await.err().unwrap().kind,
            ErrorKind::PolicyChanged
        );
        assert_eq!(
            reader.read(&request).await.err().unwrap().kind,
            ErrorKind::Denied
        );
        assert_eq!(store.reads_started(), before);
        passed(4 + n);
    }
    drop(reader);
    f.shutdown().await;
}
#[tokio::test]
async fn selector_bounds_and_actual_file_integrity_are_enforced() {
    let valid = request(3, 11);
    let split = request(2, 3);
    let f = fixture(&[(&valid, "🙂\n漢".as_bytes()), (&split, b"x")]).await;
    let (root, store) = store();
    let reader = guard(&f, store.clone()).await;
    assert_eq!(
        reader.read(&split).await.err().unwrap().kind,
        ErrorKind::Invalid
    );
    let narrow = SourceReadRequest {
        max_bytes: 1,
        ..valid.clone()
    };
    assert_eq!(
        reader.read(&narrow).await.err().unwrap().kind,
        ErrorKind::Limit
    );
    passed(7);
    let before = store.reads_started();
    let wrong = SourceReadRequest {
        version: ContentHash::of_bytes(b"other"),
        ..valid.clone()
    };
    assert_eq!(
        reader.read(&wrong).await.err().unwrap().kind,
        ErrorKind::Denied
    );
    let path = SourceReadRequest {
        source_id: SourceId::new("../../private-file").unwrap(),
        ..valid.clone()
    };
    assert_eq!(
        reader.read(&path).await.err().unwrap().kind,
        ErrorKind::Denied
    );
    assert_eq!(store.reads_started(), before);
    passed(8);
    let path = root
        .path()
        .canonicalize()
        .unwrap()
        .join(&valid.version.as_str()[7..]);
    std::fs::write(&path, b"replacement").unwrap();
    assert_eq!(
        reader.read(&valid).await.err().unwrap().kind,
        ErrorKind::Invalid
    );
    passed(9);
    #[cfg(unix)]
    {
        let backup = path.with_extension("original");
        std::fs::rename(&path, &backup).unwrap();
        std::os::unix::fs::symlink(&backup, &path).unwrap();
        assert_eq!(
            reader.read(&valid).await.err().unwrap().kind,
            ErrorKind::Denied
        );
        passed(10);
    }
    drop(reader);
    f.shutdown().await;
}
