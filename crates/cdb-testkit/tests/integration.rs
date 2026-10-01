use cdb_core::{
    admission::*, artifact::*, claim::*, contracts::*, id::*, replay::*, snapshot::*,
    CanonicalValue as V, Limits, Result, Timestamp,
};
use cdb_testkit::{assertions::*, memory::*, projection::*};
use std::{
    collections::BTreeSet,
    future::Future,
    sync::{mpsc, Arc, Barrier},
    task::{Context, Poll, Waker},
};

fn obj<const N: usize>(fields: [(&str, V); N]) -> V {
    V::object(fields.into_iter().map(|(k, v)| (k.to_owned(), v))).unwrap()
}
fn json(s: &str) -> V {
    V::parse(s.as_bytes(), Limits::default()).unwrap()
}
fn set(v: &mut V, k: &str, x: V) {
    let V::Object(o) = v else { panic!("object") };
    o.insert(k.into(), x);
}
fn backend() -> MemoryBackend {
    MemoryBackend::new(
        BackendId::new("memory").unwrap(),
        AuthorityId::new("memory:integration").unwrap(),
        GraphId::new("g").unwrap(),
        Timestamp::from_millis(0).unwrap(),
        MemoryOptions::default(),
    )
    .unwrap()
}
fn claim(id: &str, subject: &str, object: &str) -> CandidateClaim {
    let mut v = json(
        r#"{"claim_id":"c","subject_id":"s","object_id":"o","relation":"urn:rel","relation_type":"urn:Rel","subject_type":"urn:T","object_type":"urn:T","claim_type":"urn:Claim","confidence":0.8,"grounding_level":"claim_only"}"#,
    );
    set(&mut v, "claim_id", V::string(id));
    set(&mut v, "subject_id", V::string(subject));
    set(&mut v, "object_id", V::string(object));
    CandidateClaim::from_value(&v).unwrap()
}
fn batch(
    claims: Vec<CandidateClaim>,
    lifecycle: Vec<LifecycleAssertion>,
    resources: Vec<ResourceChange>,
) -> AdmissionBatch {
    AdmissionBatch::new(
        claims,
        lifecycle,
        resources,
        vec![],
        json("{}"),
        Limits::default(),
    )
    .unwrap()
}
fn artifact(name: &str, version: &str) -> PublishedArtifact {
    let bytes = format!("{name}:{version}").into_bytes();
    PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new(format!("ctxql:{name}")).unwrap(),
            VersionId::new(version).unwrap(),
            ContentHash::of_bytes(&bytes),
        ),
        bytes,
        Limits::default(),
    )
    .unwrap()
}
fn cp(pin: SnapshotRef, gen: &str) -> ProjectionCheckpoint {
    ProjectionCheckpoint::new(
        pin,
        VersionId::new("ctxql-projection/v1").unwrap(),
        VersionId::new(gen).unwrap(),
        Iri::new("ctxql:projection/v1").unwrap(),
    )
    .unwrap()
}
fn ready<T>(f: impl Future<Output = T>) -> T {
    match std::pin::pin!(f)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("fixture operation unexpectedly pending"),
    }
}

fn lifecycle(id: &str, target: &str, relation: &str, reference: &str) -> LifecycleAssertion {
    let mut v = claim(id, target, reference)
        .projection()
        .as_object()
        .unwrap()
        .clone();
    v.insert("relation".into(), V::string(relation));
    LifecycleAssertion::from_value(&V::Object(v)).unwrap()
}

#[tokio::test]
async fn reusable_backend_projection_suite_preserves_lifecycle_and_dependencies() {
    let b = backend();
    let origin = b.head().await.unwrap();
    let p = MemoryProjection::new(
        origin,
        Iri::new("ctxql:projection/v1").unwrap(),
        ProjectionOptions::default(),
    )
    .unwrap();
    let resource = DependencyRecord::new(
        "ctxql-resource/v1",
        ResourceId::new("urn:ontology").unwrap(),
        ResourceKind::Ontology,
        vec![Fact::new(
            Iri::new("urn:label").unwrap(),
            FactTerm::Reference(ResourceId::new("external-entity").unwrap()),
        )],
    )
    .unwrap();
    let c1 = claim("c1", "s", "o");
    let c2 = claim("c2", "s", "o");
    let lifecycle = lifecycle("event", "c1", "ctxql:superseded_by", "c2");
    let batches = vec![
        (
            IdempotencyKey::new("first").unwrap(),
            batch(vec![c1, c2], vec![], vec![ResourceChange::Add(resource)]),
        ),
        (
            IdempotencyKey::new("lifecycle").unwrap(),
            batch(vec![], vec![lifecycle], vec![]),
        ),
    ];
    assert_backend_projection(
        &b,
        &p,
        &batches,
        VersionId::new("live").unwrap(),
        Iri::new("ctxql:projection/v1").unwrap(),
        1000,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn directions_self_loops_and_cursors_are_exact() {
    let b = backend();
    b.admit(
        &IdempotencyKey::new("claims").unwrap(),
        &batch(
            vec![
                claim("a", "s", "o"),
                claim("b", "o", "s"),
                claim("c", "s", "s"),
            ],
            vec![],
            vec![],
        ),
    )
    .await
    .unwrap();
    let pin = b.head().await.unwrap();
    let s = b.open_snapshot(&pin).await.unwrap();
    let p = MemoryProjection::new(
        pin.clone(),
        Iri::new("ctxql:projection/v1").unwrap(),
        ProjectionOptions::default(),
    )
    .unwrap();
    p.build(
        &complete_export(s.as_ref(), 1000).await.unwrap(),
        &cp(pin.clone(), "live"),
    )
    .await
    .unwrap();
    let view = p.open_view(&pin).await.unwrap();
    let entity = EntityId::new("s").unwrap();
    for (direction, expected) in [
        (Direction::Outgoing, vec!["a", "c"]),
        (Direction::Incoming, vec!["b", "c"]),
        (Direction::Both, vec!["a", "b", "c"]),
    ] {
        let page = view
            .incident(&entity, direction, PageSize::new(10).unwrap(), None)
            .unwrap();
        assert_eq!(
            page.items()
                .iter()
                .map(|c| c.id().as_str())
                .collect::<Vec<_>>(),
            expected
        );
    }
    let first = view
        .incident(&entity, Direction::Both, PageSize::new(1).unwrap(), None)
        .unwrap();
    let cursor = first.next().unwrap();
    assert!(view
        .incident(
            &entity,
            Direction::Incoming,
            PageSize::new(1).unwrap(),
            Some(cursor)
        )
        .is_err());
    assert!(view
        .incident(
            &EntityId::new("o").unwrap(),
            Direction::Both,
            PageSize::new(1).unwrap(),
            Some(cursor)
        )
        .is_err());
    for position in ["0", "01", "999", "-1"] {
        let bad = PageCursor::new(
            pin.clone(),
            cursor.stream().clone(),
            VersionId::new(position).unwrap(),
        );
        assert!(view
            .incident(
                &entity,
                Direction::Both,
                PageSize::new(1).unwrap(),
                Some(&bad)
            )
            .is_err());
    }
    let absent = view
        .incident(
            &EntityId::new("missing").unwrap(),
            Direction::Both,
            PageSize::new(1).unwrap(),
            None,
        )
        .unwrap();
    assert!(absent.complete() && absent.items().is_empty());
    let newer = b.capture(None).await.unwrap().snapshot;
    let bad = PageCursor::new(newer, cursor.stream().clone(), cursor.position().clone());
    assert!(view
        .incident(
            &entity,
            Direction::Both,
            PageSize::new(1).unwrap(),
            Some(&bad)
        )
        .is_err());
}

#[tokio::test]
async fn incomplete_duplicate_and_dangling_exports_never_publish() {
    let b = backend();
    let pin = b.head().await.unwrap();
    let size = PageSize::new(1).unwrap();
    let record = ExportRecord::Claim(Box::new(AdmittedClaim::assign(
        claim("c", "s", "o"),
        Timestamp::from_millis(0).unwrap(),
    )));
    let cursor = PageCursor::new(
        pin.clone(),
        ResourceId::new("export").unwrap(),
        VersionId::new("1").unwrap(),
    );
    let incomplete = Page::new(vec![record.clone()], pin.clone(), Some(cursor), size).unwrap();
    assert!(CompleteExport::collect(
        pin.clone(),
        ResourceId::new("export").unwrap(),
        vec![incomplete],
        100
    )
    .is_err());
    let p = MemoryProjection::new(
        pin.clone(),
        Iri::new("ctxql:projection/v1").unwrap(),
        ProjectionOptions::default(),
    )
    .unwrap();
    let duplicate = Page::new(
        vec![record.clone(), record],
        pin.clone(),
        None,
        PageSize::new(2).unwrap(),
    )
    .unwrap();
    let export = CompleteExport::collect(
        pin.clone(),
        ResourceId::new("export").unwrap(),
        vec![duplicate],
        100,
    )
    .unwrap();
    assert!(p.build(&export, &cp(pin.clone(), "dup")).await.is_err());
    let assertion = lifecycle("assertion", "absent", "ctxql:retracted_by", "event");
    let page = Page::new(
        vec![ExportRecord::Lifecycle {
            assertion,
            transaction_time: Timestamp::from_millis(0).unwrap(),
        }],
        pin.clone(),
        None,
        size,
    )
    .unwrap();
    let export = CompleteExport::collect(
        pin.clone(),
        ResourceId::new("export").unwrap(),
        vec![page],
        100,
    )
    .unwrap();
    assert!(p.build(&export, &cp(pin, "dangling")).await.is_err());
    assert!(p.checkpoint().await.unwrap().is_none());
}

async fn recorded(b: &MemoryBackend) -> (ExecutionRun, PublishedArtifact) {
    let q = artifact("query/test", "1");
    let c = artifact("config/test", "1");
    let assembly = artifact("assembly/test", "1");
    for a in [&q, &c, &assembly] {
        ArtifactRepository::publish(b, a).await.unwrap();
    }
    let pin = b.head().await.unwrap();
    let run = ExecutionRun::new(ExecutionRunInput {
        schema: "ctxql-execution-run/v1".into(),
        id: RunId::new("run").unwrap(),
        query: q.reference().clone(),
        profile: None,
        config: c.reference().clone(),
        engine: EngineIdentity::new(
            Iri::new("ctxql:test-engine").unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(b"engine"),
        ),
        plan_hash: ContentHash::of_bytes(b"plan"),
        response_hash: ContentHash::of_bytes(b"response"),
        snapshot: pin.clone(),
        as_of: Timestamp::from_millis(0).unwrap(),
        landings: vec![],
        functions: vec![],
        footprint: ReadFootprint::new("ctxql-read-footprint/v1", pin, vec![], vec![]).unwrap(),
    })
    .unwrap();
    b.record_run(&run).await.unwrap();
    (run, assembly)
}
fn invocation(run: &ExecutionRun, assembly: &PublishedArtifact) -> V {
    let mut assembly_ref = assembly.reference().projection();
    set(&mut assembly_ref, "name", V::string("test"));
    obj([
        ("schema", V::string("ctxql-assembly-inputs/v1")),
        ("invocation_id", V::string("invocation")),
        ("assembly", assembly_ref),
        (
            "inputs",
            V::Array(vec![obj([
                ("name", V::string("primary")),
                ("required", V::Bool(true)),
                ("query", run.query().projection()),
                ("profile", V::Null),
                ("plan_hash", V::string(run.plan_hash().as_str())),
                ("run_id", V::string(run.id().as_str())),
                ("response_hash", V::string(run.response_hash().as_str())),
                ("as_of", V::string(run.as_of().canonical())),
                ("db_time", run.snapshot().projection()),
                ("replay_verdict", V::string("reproduced")),
                ("notices", V::Array(vec![])),
            ])]),
        ),
        ("product_hash", V::Null),
        ("source_verifications", V::Array(vec![])),
    ])
}
#[tokio::test]
async fn assembly_record_checks_protected_input_correspondence_without_executing_python() {
    let b = backend();
    let (run, assembly) = recorded(&b).await;
    let original = invocation(&run, &assembly);
    let good = AssemblyInvocation::from_value(&original).unwrap();
    b.record_assembly(&good).await.unwrap();
    let head = b.head().await.unwrap();
    b.record_assembly(&good).await.unwrap();
    assert_eq!(head, b.head().await.unwrap());
    for (key, replacement) in [
        ("query", assembly.reference().projection()),
        ("profile", run.query().projection()),
        ("as_of", V::string("1970-01-01T00:00:00.001Z")),
        (
            "plan_hash",
            V::string(ContentHash::of_bytes(b"bad").as_str()),
        ),
        (
            "response_hash",
            V::string(ContentHash::of_bytes(b"bad").as_str()),
        ),
        ("run_id", V::string("missing")),
    ] {
        let mut bad = original.clone();
        set(&mut bad, "invocation_id", V::string(format!("bad-{key}")));
        let V::Object(o) = &mut bad else {
            unreachable!()
        };
        let V::Array(inputs) = o.get_mut("inputs").unwrap() else {
            unreachable!()
        };
        set(&mut inputs[0], key, replacement);
        let bad = AssemblyInvocation::from_value(&bad).unwrap();
        assert!(b.record_assembly(&bad).await.is_err(), "{key}");
        assert_eq!(head, b.head().await.unwrap());
    }
}

#[tokio::test]
async fn publication_holds_mutation_gate_until_sink_finishes() {
    let b = backend();
    let principal = b
        .provision(PrincipalId::new("p").unwrap(), true, BTreeSet::new())
        .unwrap();
    let context = b.current(&principal).await.unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let publisher = b.clone();
    let thread = std::thread::spawn(move || {
        let mut sink = move || -> Result<()> {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(())
        };
        ready(PolicyService::publish(
            &publisher, &principal, &context, &mut sink,
        ))
        .unwrap();
    });
    entered_rx.recv().unwrap();
    assert!(b.publication_gate_busy().unwrap());
    let barrier = Arc::new(Barrier::new(2));
    let worker_barrier = barrier.clone();
    let mutator = b.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let mutation = std::thread::spawn(move || {
        worker_barrier.wait();
        mutator
            .provision(PrincipalId::new("other").unwrap(), true, BTreeSet::new())
            .unwrap();
        done_tx.send(()).unwrap();
    });
    barrier.wait();
    assert!(done_rx.try_recv().is_err());
    release_tx.send(()).unwrap();
    thread.join().unwrap();
    mutation.join().unwrap();
    done_rx.recv().unwrap();
    assert!(!b.publication_gate_busy().unwrap());
}

#[tokio::test]
async fn default_policy_handles_opaque_ids_and_published_artifacts() {
    let b = backend();
    b.admit(
        &IdempotencyKey::new("opaque").unwrap(),
        &batch(vec![claim("opaque-claim", "s", "o")], vec![], vec![]),
    )
    .await
    .unwrap();
    let artifact = artifact("config/policy", "1");
    ArtifactRepository::publish(&b, &artifact).await.unwrap();
    let principal = b
        .provision(
            PrincipalId::new("p").unwrap(),
            true,
            BTreeSet::from([Iri::new("https://policy.test/reader").unwrap()]),
        )
        .unwrap();
    b.set_policy(cdb_core::policy::PolicySet::from_value(&json(r#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[
      {"@id":"https://policy.test/p","@type":["https://ns.flur.ee/db#AccessPolicy","https://policy.test/reader"],
       "https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true}]}"#)).unwrap()).unwrap();
    let context = b.current(&principal).await.unwrap();
    assert!(b
        .resource_allowed(&context, &ResourceId::new("opaque-claim").unwrap())
        .unwrap());
    assert!(b
        .resource_allowed(
            &context,
            &ResourceId::new(artifact.reference().iri().as_str()).unwrap()
        )
        .unwrap());
    assert!(!b
        .resource_allowed(&context, &ResourceId::new("missing").unwrap())
        .unwrap());
}

#[tokio::test]
async fn admission_origin_and_clock_roles_are_content_bound() {
    let a = backend();
    let b = backend();
    let receipt = a
        .admit(
            &IdempotencyKey::new("key").unwrap(),
            &batch(vec![], vec![], vec![]),
        )
        .await
        .unwrap();
    let capture = b.capture(None).await.unwrap();
    assert_ne!(receipt.snapshot(), &capture.snapshot);
    let records = complete_export(
        a.open_snapshot(receipt.snapshot()).await.unwrap().as_ref(),
        1000,
    )
    .await
    .unwrap();
    assert!(records.records().iter().any(|r| matches!(r,ExportRecord::Resource(r) if r.facts().iter().any(|f| f.predicate().as_str()=="urn:ctxql:testkit:admission"))));
    let c = backend();
    let d = backend();
    let x = c
        .admit(
            &IdempotencyKey::new("one").unwrap(),
            &batch(vec![], vec![], vec![]),
        )
        .await
        .unwrap();
    let y = d
        .admit(
            &IdempotencyKey::new("two").unwrap(),
            &batch(vec![], vec![], vec![]),
        )
        .await
        .unwrap();
    assert_ne!(x.snapshot(), y.snapshot());
}
