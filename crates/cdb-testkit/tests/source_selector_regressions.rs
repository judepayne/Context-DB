use cdb_core::{
    artifact::ArtifactRef,
    contracts::{AuthorizedSelectorResolver, CandidateExtractor, SourceReader},
    evidence::{EvidenceSelector, Utf8Span},
    id::*,
    source::*,
    CanonicalValue as V, ErrorKind, Limits, Timestamp,
};
use cdb_testkit::sources::*;

fn obj<const N: usize>(fields: [(&str, V); N]) -> V {
    V::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

fn span(start: usize, end: usize) -> EvidenceSelector {
    EvidenceSelector::Span(Utf8Span::new(start, end).unwrap())
}

async fn distinguish(left: EvidenceSelector, right: EvidenceSelector) {
    let bytes = b"abcabc";
    let sources = ScriptedSources::new(
        vec![ImmutableSource::new(
            SourceId::new("s").unwrap(),
            bytes.to_vec(),
        )],
        SourceOptions::default(),
    )
    .unwrap();
    let mut requests = Vec::new();
    for selector in [left, right] {
        let request = SourceReadRequest {
            source_id: SourceId::new("s").unwrap(),
            version: ContentHash::of_bytes(bytes),
            selector,
            max_bytes: bytes.len(),
        };
        let source = sources.read(&request).await.unwrap();
        assert_eq!(source.selector(), &request.selector);
        let auth = sources.authorize(&request).unwrap();
        assert_eq!(source, sources.resolve(&auth, &request).await.unwrap());
        requests.push(ExtractionRequest {
            source,
            extractor: ArtifactRef::new(
                Iri::new("urn:extractor").unwrap(),
                VersionId::new("1").unwrap(),
                ContentHash::of_bytes(b"extractor"),
            ),
            settings: obj([] as [(&str, V); 0]),
            observed_at: Timestamp::parse("2025-01-01T00:00:00.000Z").unwrap(),
            max_candidates: 1,
        });
    }
    assert_eq!(requests[0].source.bytes(), requests[1].source.bytes());
    assert_ne!(requests[0].source, requests[1].source);
    let script = |index: usize| ExtractionScript {
        request: requests[index].clone(),
        result: ExtractionResult::new(vec![], obj([("script", V::integer(index as u64))]), 1)
            .unwrap(),
    };
    for index in 0..2 {
        let extractor =
            ScriptedExtractor::new(vec![script(index)], SourceOptions::default()).unwrap();
        assert_eq!(
            extractor
                .extract(&requests[1 - index], Limits::default())
                .await
                .unwrap_err()
                .kind,
            ErrorKind::NotFound,
        );
    }
    let extractor =
        ScriptedExtractor::new(vec![script(0), script(1)], SourceOptions::default()).unwrap();
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(
            extractor
                .extract(request, Limits::default())
                .await
                .unwrap()
                .provenance(),
            script(index).result.provenance(),
        );
    }
    assert!(ScriptedExtractor::new(vec![script(0), script(0)], SourceOptions::default()).is_err());
}

#[tokio::test]
async fn equal_bytes_at_distinct_spans_keep_identity() {
    distinguish(span(0, 3), span(3, 6)).await;
}

#[tokio::test]
async fn empty_spans_at_distinct_offsets_keep_identity() {
    distinguish(span(0, 0), span(3, 3)).await;
}

#[tokio::test]
async fn whole_document_and_full_span_keep_identity() {
    distinguish(EvidenceSelector::WholeDocument, span(0, 6)).await;
}
