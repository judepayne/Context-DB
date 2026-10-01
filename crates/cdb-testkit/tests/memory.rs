use cdb_core::{
    admission::*, contracts::*, id::*, snapshot::*, CanonicalValue, ErrorKind, Limits, Timestamp,
};
use cdb_core::{artifact::*, claim::CandidateClaim, policy::PolicySet};
use cdb_testkit::memory::*;
fn candidate(id: &str) -> CandidateClaim {
    let json = format!(
        r#"{{"claim_id":"{id}","subject_id":"https://test/s","relation":"https://test/r","object_id":"https://test/o","relation_type":"https://test/T","subject_type":"https://test/T","object_type":"https://test/T","claim_type":"https://test/T","confidence":1,"grounding_level":"claim_only","valid_time":"1900-01-01T00:00:00Z"}}"#
    );
    CandidateClaim::from_value(&CanonicalValue::parse(json.as_bytes(), Limits::default()).unwrap())
        .unwrap()
}
fn populated(
    claims: Vec<CandidateClaim>,
    resources: Vec<ResourceChange>,
    artifacts: Vec<PublishedArtifact>,
) -> AdmissionBatch {
    AdmissionBatch::new(
        claims,
        vec![],
        resources,
        artifacts,
        CanonicalValue::parse(b"{}", Limits::default()).unwrap(),
        Limits::default(),
    )
    .unwrap()
}
fn resource(value: &str) -> DependencyRecord {
    DependencyRecord::new(
        "ctxql-resource/v1",
        ResourceId::new("https://test/resource").unwrap(),
        ResourceKind::Ontology,
        vec![Fact::new(
            Iri::new("https://test/p").unwrap(),
            FactTerm::Reference(ResourceId::new(value).unwrap()),
        )],
    )
    .unwrap()
}
#[tokio::test]
async fn immutable_claims_dependencies_artifacts_and_pages() {
    let b = backend(MemoryOptions::default());
    let r = resource("old");
    let a = PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new("https://test/artifact").unwrap(),
            VersionId::new("v1").unwrap(),
            ContentHash::of_bytes(b"bytes"),
        ),
        b"bytes".to_vec(),
        Limits::default(),
    )
    .unwrap();
    let input = populated(
        vec![candidate("c1"), candidate("c2")],
        vec![ResourceChange::Add(r.clone())],
        vec![a.clone()],
    );
    let key = IdempotencyKey::new("first").unwrap();
    let first = b.admit(&key, &input).await.unwrap();
    assert_eq!(first.transaction_time().millis(), -100);
    let old = b.open_snapshot(first.snapshot()).await.unwrap();
    let replacement = resource("new");
    let update = populated(
        vec![],
        vec![ResourceChange::ReplaceMutable {
            previous: ContentHash::of_bytes(
                &r.projection().canonical_bytes(Limits::default()).unwrap(),
            ),
            record: replacement.clone(),
        }],
        vec![],
    );
    b.admit(&IdempotencyKey::new("replace").unwrap(), &update)
        .await
        .unwrap();
    assert_eq!(old.resource(r.id()).await.unwrap(), Some(r.clone()));
    assert_eq!(old.artifact(a.reference()).await.unwrap(), Some(a.clone()));
    assert_eq!(
        b.open_snapshot(&b.head().await.unwrap())
            .await
            .unwrap()
            .resource(r.id())
            .await
            .unwrap(),
        Some(replacement)
    );
    let page = old.export(None, PageSize::new(2).unwrap()).await.unwrap();
    assert_eq!(page.items().len(), 2);
    assert_eq!(
        old.export(page.next(), PageSize::new(2).unwrap())
            .await
            .unwrap()
            .items()
            .len(),
        2
    );
    let before = b.head().await.unwrap();
    assert_eq!(
        b.admit(&key, &update).await.unwrap_err().kind,
        ErrorKind::Conflict
    );
    assert_eq!(
        b.admit(
            &IdempotencyKey::new("duplicate").unwrap(),
            &populated(vec![candidate("fresh"), candidate("c1")], vec![], vec![])
        )
        .await
        .unwrap_err()
        .kind,
        ErrorKind::Conflict
    );
    assert_eq!(b.head().await.unwrap(), before);
    assert_eq!(
        ArtifactRepository::publish(&b, &a).await.unwrap(),
        *a.reference()
    );
    let wrong = ArtifactRef::new(
        a.reference().iri().clone(),
        VersionId::new("wrong").unwrap(),
        a.reference().hash().clone(),
    );
    assert!(b.lookup(&wrong).await.unwrap().is_none());
    let second =
        PublishedArtifact::new(wrong.clone(), a.content().to_vec(), Limits::default()).unwrap();
    ArtifactRepository::publish(&b, &second).await.unwrap();
    assert!(b.lookup(a.reference()).await.unwrap().is_some());
    assert!(b.lookup(&wrong).await.unwrap().is_some());
    assert!(old.artifact(&wrong).await.unwrap().is_none());
    let spoof = ArtifactRef::new(
        a.reference().iri().clone(),
        a.reference().version().clone(),
        ContentHash::of_bytes(b"different"),
    );
    assert!(b.lookup(&spoof).await.is_err());
}
#[tokio::test]
async fn current_policy_uses_current_resource_classes() {
    let b = backend(MemoryOptions::default());
    let r = resource("old");
    let first = b
        .admit(
            &IdempotencyKey::new("r").unwrap(),
            &populated(vec![], vec![ResourceChange::Add(r.clone())], vec![]),
        )
        .await
        .unwrap();
    let principal_class = Iri::new("https://test/member").unwrap();
    let class = Iri::new("https://test/class").unwrap();
    let p = b
        .provision(
            PrincipalId::new("member").unwrap(),
            true,
            [principal_class].into(),
        )
        .unwrap();
    let policy=PolicySet::parse(br#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{"@id":"https://test/policy","@type":["https://ns.flur.ee/db#AccessPolicy","https://test/member"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true,"https://ns.flur.ee/db#onClass":"https://test/class"}]}"#,Limits::default()).unwrap();
    b.set_policy(policy).unwrap();
    b.set_classes(r.id().clone(), [class].into()).unwrap();
    let c = b.current(&p).await.unwrap();
    assert!(b.resource_allowed(&c, r.id()).unwrap());
    b.set_classes(r.id().clone(), Default::default()).unwrap();
    assert!(b.resource_allowed(&c, r.id()).is_err());
    let c = b.current(&p).await.unwrap();
    assert!(!b.resource_allowed(&c, r.id()).unwrap());
    assert_eq!(
        b.open_snapshot(first.snapshot())
            .await
            .unwrap()
            .resource(r.id())
            .await
            .unwrap(),
        Some(r)
    );
}
fn backend(options: MemoryOptions) -> MemoryBackend {
    MemoryBackend::new(
        BackendId::new("memory").unwrap(),
        AuthorityId::new("memory:test").unwrap(),
        GraphId::new("g").unwrap(),
        Timestamp::from_millis(-100).unwrap(),
        options,
    )
    .unwrap()
}
fn batch() -> AdmissionBatch {
    AdmissionBatch::new(
        vec![],
        vec![],
        vec![],
        vec![],
        CanonicalValue::parse(b"{}", Limits::default()).unwrap(),
        Limits::default(),
    )
    .unwrap()
}
#[tokio::test]
async fn atomic_clock_receipts_history() {
    let b = backend(MemoryOptions::default());
    let k = IdempotencyKey::new("k").unwrap();
    let batch = batch();
    assert_admission_contract(&b, &k, &batch).await.unwrap();
    let first = b.receipt(&k).await.unwrap().unwrap();
    assert_eq!(first.transaction_time().millis(), -100);
    b.set_wall(Timestamp::from_millis(-200).unwrap()).unwrap();
    let c = b.capture(None).await.unwrap();
    assert_eq!(c.as_of.millis(), -100);
    let next = b
        .admit(&IdempotencyKey::new("next").unwrap(), &batch)
        .await
        .unwrap();
    assert_eq!(next.transaction_time().millis(), -99);
    assert_eq!(b.admit(&k, &batch).await.unwrap(), first);
    let changes = b
        .changes(
            first.snapshot(),
            next.snapshot(),
            None,
            PageSize::new(1).unwrap(),
        )
        .await
        .unwrap();
    assert!(changes.next().is_some());
    assert!(b
        .changes(
            &c.snapshot,
            next.snapshot(),
            changes.next(),
            PageSize::new(1).unwrap()
        )
        .await
        .is_err());
    assert_eq!(
        b.changes(
            first.snapshot(),
            next.snapshot(),
            changes.next(),
            PageSize::new(1).unwrap()
        )
        .await
        .unwrap()
        .items()
        .len(),
        1
    );
}
#[tokio::test]
async fn faults_future_limits_and_overflow() {
    let b = backend(MemoryOptions::default());
    let old = b.head().await.unwrap();
    let k = IdempotencyKey::new("k").unwrap();
    b.inject_fault(MemoryFault::BeforePublication).unwrap();
    assert!(b.admit(&k, &batch()).await.is_err());
    assert_eq!(b.head().await.unwrap(), old);
    assert!(b.receipt(&k).await.unwrap().is_none());
    assert_eq!(
        b.capture(Some(Timestamp::from_millis(0).unwrap()))
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    assert_eq!(b.head().await.unwrap(), old);
    b.inject_fault(MemoryFault::LostAcknowledgement).unwrap();
    assert!(b.admit(&k, &batch()).await.is_err());
    assert_eq!(
        b.admit(&k, &batch()).await.unwrap(),
        b.receipt(&k).await.unwrap().unwrap()
    );
    b.set_wall(Timestamp::parse("9999-12-31T23:59:59.999Z").unwrap())
        .unwrap();
    b.capture(None).await.unwrap();
    let old = b.head().await.unwrap();
    assert_eq!(
        b.admit(&IdempotencyKey::new("overflow").unwrap(), &batch())
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Range
    );
    assert_eq!(b.head().await.unwrap(), old);
    let tiny = backend(MemoryOptions {
        history: 1,
        ..MemoryOptions::default()
    });
    let old = tiny.head().await.unwrap();
    assert!(tiny.capture(None).await.is_err());
    assert_eq!(tiny.head().await.unwrap(), old);
}
#[tokio::test]
async fn hints_pending_lagged_closed_and_policy_epoch() {
    let b = backend(MemoryOptions {
        hints: 1,
        ..MemoryOptions::default()
    });
    let mut hints = b.subscribe().await.unwrap();
    let mut pending = hints.next();
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(pending.as_mut().poll(cx).is_pending()))
            .await
    );
    drop(pending);
    b.capture(None).await.unwrap();
    b.capture(None).await.unwrap();
    assert_eq!(hints.next().await.unwrap(), ChangeHint::Lagged);
    b.close_hints().unwrap();
    assert_eq!(hints.next().await.unwrap(), ChangeHint::Closed);
    let p = b
        .provision(
            PrincipalId::new("private-sentinel").unwrap(),
            true,
            Default::default(),
        )
        .unwrap();
    let c = b.current(&p).await.unwrap();
    let mut called = false;
    PolicyService::publish(&b, &p, &c, &mut || {
        called = true;
        Ok(())
    })
    .await
    .unwrap();
    assert!(called);
    b.capture(None).await.unwrap();
    let e = PolicyService::publish(&b, &p, &c, &mut || panic!("stale sink"))
        .await
        .unwrap_err();
    assert_eq!(e.public_json(), "{\"error\":\"policy_changed\"}");
    let other = backend(MemoryOptions::default());
    assert!(other.current(&p).await.is_err());
    let foreign = SnapshotRef::new(
        BackendId::new("foreign").unwrap(),
        b.head().await.unwrap().pin().clone(),
    );
    assert!(b.open_snapshot(&foreign).await.is_err());
    assert!(b
        .changes(&foreign, &foreign, None, PageSize::new(1).unwrap())
        .await
        .is_err());
}

#[tokio::test]
async fn metadata_history_reserved_namespace_and_low_bytes() {
    let b = backend(MemoryOptions::default());
    let genesis = b.head().await.unwrap();
    let id = PrincipalId::new("alice").unwrap();
    b.provision(id.clone(), true, Default::default()).unwrap();
    let first = b.head().await.unwrap();
    b.provision(id, false, Default::default()).unwrap();
    let old = b.open_snapshot(&first).await.unwrap();
    let records = old.export(None, PageSize::new(100).unwrap()).await.unwrap();
    assert_eq!(records.items().len(), 1);
    let ExportRecord::Resource(record) = &records.items()[0] else {
        panic!("metadata resource")
    };
    assert_eq!(record.kind(), ResourceKind::Identity);
    let bytes = record
        .projection()
        .canonical_bytes(Limits::default())
        .unwrap();
    assert!(String::from_utf8(bytes).unwrap().contains("enabled"));
    let history = b
        .changes(
            &genesis,
            &b.head().await.unwrap(),
            None,
            PageSize::new(100).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(history.items().len(), 2);
    assert!(history.items().iter().all(|c| c.changes().len() == 1));
    let key = IdempotencyKey::new("reserved").unwrap();
    assert!(b
        .admit(
            &key,
            &populated(
                vec![candidate("urn:ctxql:testkit:internal:spoof")],
                vec![],
                vec![]
            )
        )
        .await
        .is_err());
    let low = backend(MemoryOptions {
        bytes: 128,
        ..MemoryOptions::default()
    });
    let before = low.head().await.unwrap();
    let batch = populated(vec![candidate("small")], vec![], vec![]);
    assert_eq!(
        low.admit(&key, &batch).await.unwrap_err().kind,
        ErrorKind::Limit
    );
    assert_eq!(low.head().await.unwrap(), before);
    assert!(low.receipt(&key).await.unwrap().is_none());
}

#[tokio::test]
async fn mutation_before_publish_barrier_rejects_stale_context() {
    let b = backend(MemoryOptions::default());
    let id = PrincipalId::new("barrier").unwrap();
    let p = b.provision(id.clone(), true, Default::default()).unwrap();
    let context = b.current(&p).await.unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let worker = b.clone();
    let signal = barrier.clone();
    let thread = std::thread::spawn(move || {
        worker.provision(id, false, Default::default()).unwrap();
        signal.wait();
    });
    barrier.wait();
    let mut invoked = false;
    let mut sink = || {
        invoked = true;
        Ok(())
    };
    assert_eq!(
        PolicyService::publish(&b, &p, &context, &mut sink)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::PolicyChanged
    );
    assert!(!invoked);
    thread.join().unwrap();
}

#[tokio::test]
async fn run_exact_snapshot_references_and_history() {
    use cdb_core::replay::*;
    let b = backend(MemoryOptions::default());
    let genesis = b.head().await.unwrap();
    let content = b"{}".to_vec();
    let reference = ArtifactRef::new(
        Iri::new("urn:test:query").unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(&content),
    );
    let artifact = PublishedArtifact::new(reference.clone(), content, Limits::default()).unwrap();
    ArtifactRepository::publish(&b, &artifact).await.unwrap();
    let pin = b.head().await.unwrap();
    let make = |id: &str, snapshot: SnapshotRef, used: Vec<ReadDependency>| {
        ExecutionRun::new(ExecutionRunInput {
            schema: "ctxql-execution-run/v1".into(),
            id: RunId::new(id).unwrap(),
            query: reference.clone(),
            profile: None,
            config: reference.clone(),
            engine: EngineIdentity::new(
                Iri::new("urn:test:engine").unwrap(),
                VersionId::new("1").unwrap(),
                ContentHash::of_bytes(b"engine"),
            ),
            plan_hash: ContentHash::of_bytes(b"plan"),
            response_hash: ContentHash::of_bytes(b"response"),
            as_of: Timestamp::parse("2025-01-01T00:00:00Z").unwrap(),
            footprint: ReadFootprint::new(
                "ctxql-read-footprint/v1",
                snapshot.clone(),
                used,
                vec![],
            )
            .unwrap(),
            snapshot,
            landings: vec![],
            functions: vec![],
        })
        .unwrap()
    };
    assert!(b.record_run(&make("past", genesis, vec![])).await.is_err());
    assert!(b
        .record_run(&make(
            "missing",
            pin.clone(),
            vec![ReadDependency::Resource(
                ResourceId::new("missing").unwrap()
            )]
        ))
        .await
        .is_err());
    assert_eq!(b.head().await.unwrap(), pin);
    let run = make(
        "valid",
        pin.clone(),
        vec![ReadDependency::Artifact(reference.clone())],
    );
    b.record_run(&run).await.unwrap();
    assert_eq!(b.run(run.id()).await.unwrap(), Some(run.clone()));
    let head = b.head().await.unwrap();
    b.record_run(&run).await.unwrap();
    assert_eq!(b.head().await.unwrap(), head);
    let changes = b
        .changes(&pin, &head, None, PageSize::new(100).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        changes.items()[0].changes()[0],
        RecordChange::Resource(ResourceChange::Add(_))
    ));
}
