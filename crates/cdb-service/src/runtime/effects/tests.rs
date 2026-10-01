use super::*;
use cdb_core::{artifact::ArtifactRef, id::*, projection::FunctionRootProjection};
const SOURCE: &[u8] = br#"{"schema":"ctxql-external-function/v1","name":"score","version":"1","implementation":{"implementation":"urn:test:native","version":"1","build":"sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f","model":null},"input_schema":{"type":"number"},"output_schema":{"type":"number"},"semantic_parameters":{},"capabilities":[],"declarations":{"deterministic":true,"order_independent":true,"retry_safe":true,"batching":"none"}}"#;
fn source() -> (Arc<ExternalFunctionManifest>, FunctionManifest) {
    let p = PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new("urn:manifest").unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(SOURCE),
        ),
        SOURCE.to_vec(),
        Limits::default(),
    )
    .unwrap();
    (
        Arc::new(ExternalFunctionManifest::from_published(&p, Limits::default()).unwrap()),
        FunctionManifest::from_published(ResourceId::new("score").unwrap(), &p, Limits::default())
            .unwrap(),
    )
}
fn ledger(max_calls: u64) -> EffectLedger {
    EffectLedger::new(
        EffectLimits {
            max_groups: 4,
            max_calls,
            max_pending_bytes: 4096,
            head_bytes: 1024,
            values: Limits::default(),
        },
        vec![(source().0, ResourceId::new("urn:destination").unwrap())],
    )
    .unwrap()
}
fn lane(evaluation: u64, predicate: u64) -> LaneIdentityV3 {
    LaneIdentityV3 {
        phase: LanePhaseV3::Walk,
        evaluation,
        predicate,
        attempt: 0,
        ordinal: 0,
    }
}
#[test]
fn later_completion_waits_for_all_earlier_predicates_and_retains_owner() {
    struct Owner(Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let ledger = ledger(10);
    let first = lane(1, 0);
    let tail = lane(2, 0);
    ledger.open_group(first.into()).unwrap();
    ledger.open_group(tail.into()).unwrap();
    let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    ledger
        .begin(tail, 0, "score", &V::integer(30), 16)
        .unwrap()
        .complete_owned(&V::integer(31), Box::new(Owner(dropped.clone())))
        .unwrap();
    ledger.close_group(tail.into()).unwrap();
    ledger
        .begin(first, 0, "score", &V::integer(10), 16)
        .unwrap()
        .complete(&V::integer(11))
        .unwrap();
    // Predicate 1 is reached after predicate 0. Closing a predicate is NOT enough
    // to advance encounter indices past its still-live candidate.
    ledger
        .begin(lane(1, 1), 0, "score", &V::integer(20), 16)
        .unwrap()
        .complete(&V::integer(21))
        .unwrap();
    assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(ledger.pending_bytes().unwrap() > 0);
    ledger.close_group(first.into()).unwrap();
    assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(ledger.pending_bytes().unwrap(), 0);
    let result = ledger.finish().unwrap().remove(0);
    let (_, m) = source();
    for (output, values, actual) in [
        (false, [10, 20, 30], result.input_root),
        (true, [11, 21, 31], result.output_root),
    ] {
        let hashes = values
            .into_iter()
            .enumerate()
            .map(|(i, v)| {
                FunctionCallProjection::new(output, &m, i as u64, V::integer(v))
                    .unwrap()
                    .canonical()
                    .hash(Limits::default())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            FunctionRootProjection::new(output, &m, &hashes)
                .unwrap()
                .canonical()
                .hash(Limits::default())
                .unwrap()
        );
    }
}
#[test]
fn incomplete_duplicate_and_overbudget_effects_cannot_finish() {
    let l = ledger(1);
    let id = lane(1, 0);
    l.open_group(id.into()).unwrap();
    drop(l.begin(id, 0, "score", &V::integer(1), 16).unwrap());
    assert!(l.finish().is_err());
    let l = ledger(1);
    l.open_group(id.into()).unwrap();
    l.begin(id, 0, "score", &V::integer(1), 16)
        .unwrap()
        .complete(&V::integer(1))
        .unwrap();
    assert!(l.begin(id, 1, "score", &V::integer(1), 16).is_err());
    assert!(l.finish().is_err());
    let l = ledger(10);
    l.open_group(id.into()).unwrap();
    assert!(l.begin(id, 0, "score", &V::integer(1), 4096).is_err());
    assert!(l.finish().is_err());
}
#[test]
fn head_streams_a_hundred_thousand_calls_without_payload_growth() {
    let l = ledger(100_000);
    let id = lane(1, 0);
    l.open_group(id.into()).unwrap();
    let (_, m) = source();
    let mut oracle = FunctionRootStream::new(false, &m, Limits::default(), 100_000).unwrap();
    for n in 0..100_000 {
        let value = V::integer(n);
        l.begin(id, n, "score", &value, 16)
            .unwrap()
            .complete(&value)
            .unwrap();
        assert_eq!(l.pending_bytes().unwrap(), 0);
        oracle
            .push(
                &FunctionCallProjection::new(false, &m, n, value)
                    .unwrap()
                    .canonical()
                    .hash(Limits::default())
                    .unwrap(),
            )
            .unwrap();
    }
    l.close_group(id.into()).unwrap();
    let result = l.finish().unwrap().remove(0);
    assert_eq!(result.count, 100_000);
    assert_eq!(result.input_root, oracle.finish().unwrap());
}
