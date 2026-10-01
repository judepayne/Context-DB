mod common_p3;
use cdb_core::{
    admission::*, claim::*, contracts::*, id::*, policy::PolicySet, snapshot::*,
    storage_origin::RecordOrigin, CanonicalValue as V, ErrorKind, Limits, Timestamp,
};
use cdb_engine::{
    compiler::{compile, QuerySource},
    execution::*,
    options::CompileOptions,
};
use cdb_testkit::reference_fixture::{artifact, FixtureBuilder, CONFIG};
use common_p3::{reader_policy, NativeFixture};
use std::sync::{atomic::AtomicBool, Arc, Mutex};

const A: &str = "https://s/A";
const B: &str = "https://s/B";
const EDGE: &str = "https://s/edge";
fn base() -> FixtureBuilder {
    let mut b = FixtureBuilder::new();
    b.entity(A, Some("A"))
        .unwrap()
        .entity(B, Some("B"))
        .unwrap();
    b.edge(
        EDGE,
        A,
        ClaimObject::Entity(EntityId::new(B).unwrap()),
        "0.7",
    )
    .unwrap();
    b
}
fn tick(f: &NativeFixture) {
    for _ in 0..10 {
        f.advance();
    }
}
fn tag(id: &str) {
    println!("P3_CASE {{\"id\":\"{id}\",\"outcome\":\"passed\"}}");
}
fn query(seed: &str, cutoff: Option<Timestamp>, predicate: &str) -> String {
    let time = cutoff
        .map(|t| format!(",\"as_of\":\"{}\"", t.canonical()))
        .unwrap_or_default();
    format!(
        r#"{{"about":[{{"from":["{seed}"],"match":"exact"}}],"bounds":{{"max_depth":1,"seed_limit":1{time}}},"walk":{{"predicates":[{predicate}]}},"return":{{"explain":true}}}}"#
    )
}
async fn run(
    f: &NativeFixture,
    p: &dyn ViewProvider,
    q: &str,
    stale: bool,
    options: ExecutionOptions,
) -> (cdb_core::Result<()>, Vec<u8>) {
    let draft = compile(
        QuerySource::inline(q.as_bytes()),
        None,
        &f.config,
        CompileOptions::default(),
    )
    .unwrap();
    let mut bytes = vec![];
    let mut sink = |b: &[u8]| {
        bytes.extend_from_slice(b);
        Ok(())
    };
    let r = if stale {
        execute_with_consistency(
            draft,
            f.backend.as_ref(),
            f.backend.as_ref(),
            &f.principal,
            p,
            Consistency::AllowStale,
            options,
            &mut sink,
        )
        .await
    } else {
        execute(
            draft,
            f.backend.as_ref(),
            f.backend.as_ref(),
            &f.principal,
            p,
            options,
            &mut sink,
        )
        .await
    };
    (r, bytes)
}
async fn value(f: &NativeFixture, q: &str) -> V {
    let (r, b) = run(f, &f.provider, q, false, ExecutionOptions::default()).await;
    r.unwrap();
    V::parse(&b, Limits::default()).unwrap()
}
fn paths(v: &V) -> Vec<Vec<&str>> {
    v.field("paths")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            p.field("claim_ids")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap())
                .collect()
        })
        .collect()
}
async fn admit(
    f: &NativeFixture,
    key: &str,
    resources: Vec<ResourceChange>,
    lifecycle: Vec<LifecycleAssertion>,
) -> Timestamp {
    tick(f);
    let batch = AdmissionBatch::new(
        vec![],
        lifecycle,
        resources,
        vec![],
        V::Object(Default::default()),
        Limits::default(),
    )
    .unwrap();
    f.backend
        .admit(&IdempotencyKey::new(key).unwrap(), &batch)
        .await
        .unwrap()
        .transaction_time()
}
fn entity(id: &str, label: &str) -> DependencyRecord {
    let mut b = FixtureBuilder::new();
    b.entity(id, Some(label)).unwrap();
    match &b.into_batch().unwrap().resources()[0] {
        ResourceChange::Add(r) => r.clone(),
        _ => unreachable!(),
    }
}
async fn deny(f: &NativeFixture, target: &str, key: &str) {
    let mut state = f.backend.policy_state().await.unwrap();
    let mut p = state.policy.projection().as_object().unwrap().clone();
    let mut rules = p["policies"].as_array().unwrap().to_vec();
    rules.push(V::parse(format!(r#"{{"@id":"https://s/{key}","@type":["https://ns.flur.ee/db#AccessPolicy","https://fixture.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":false,"https://ns.flur.ee/db#onSubject":"{target}"}}"#).as_bytes(), Limits::default()).unwrap());
    p.insert("policies".into(), V::Array(rules));
    state.policy = PolicySet::from_value(&V::Object(p)).unwrap();
    tick(f);
    f.backend
        .set_policy_state(&IdempotencyKey::new(key).unwrap(), &state)
        .await
        .unwrap();
    tick(f);
}
struct Stale<'a> {
    f: &'a NativeFixture,
    old: SnapshotRef,
    requested: Mutex<Option<CapturedSnapshot>>,
}
impl ViewProvider for Stale<'_> {
    fn propose_stale<'a>(
        &'a self,
        c: &'a CapturedSnapshot,
        _: &'a ExecutionOptions,
    ) -> IoFuture<'a, Option<SnapshotRef>> {
        Box::pin(async move {
            *self.requested.lock().unwrap() = Some(c.clone());
            Ok(Some(self.old.clone()))
        })
    }
    fn open<'a>(
        &'a self,
        c: &'a CapturedSnapshot,
        o: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        self.f.provider.open(c, o)
    }
}

#[tokio::test]
async fn multi_admission_entity_label_cutoff() {
    let mut b = base();
    b.resource(entity("https://s/early", "Early"));
    let f = NativeFixture::new(b, reader_policy(), 1).await;
    let initial = f
        .backend
        .receipt(&IdempotencyKey::new("fixture").unwrap())
        .await
        .unwrap()
        .unwrap()
        .transaction_time();
    let later = admit(
        &f,
        "late",
        vec![ResourceChange::Add(entity("https://s/late", "Late"))],
        vec![],
    )
    .await;
    tick(&f);
    for (cutoff, expected) in [
        (initial, vec![A, B, "https://s/early"]),
        (later, vec![A, B, "https://s/early", "https://s/late"]),
    ] {
        let captured = f.backend.capture(Some(cutoff)).await.unwrap();
        let prepared = f
            .provider
            .open(&captured, &ExecutionOptions::default())
            .await
            .unwrap();
        let ids: Vec<_> = prepared
            .landing
            .entries()
            .iter()
            .filter(|e| e.label.is_some())
            .map(|e| e.id.as_str())
            .collect();
        assert_eq!(ids, expected);
        assert!(prepared
            .landing
            .entries()
            .iter()
            .all(|e| e.dependencies.len() == 2));
    }
    assert_eq!(
        paths(&value(&f, &query("A", Some(initial), "")).await),
        vec![vec![EDGE]]
    );
    assert!(paths(&value(&f, &query("Late", Some(initial), "")).await).is_empty());
    tag("P3-S001");
    f.shutdown().await;
}
#[tokio::test]
async fn returned_image_is_not_backdated() {
    let f = NativeFixture::new(base(), reader_policy(), 1).await;
    let a = entity(A, "A");
    let b = entity(A, "Changed");
    let hash = |r: &DependencyRecord| {
        ContentHash::of_bytes(&r.projection().canonical_bytes(Limits::default()).unwrap())
    };
    let cutoff = admit(
        &f,
        "to-b",
        vec![ResourceChange::ReplaceMutable {
            previous: hash(&a),
            record: b.clone(),
        }],
        vec![],
    )
    .await;
    admit(
        &f,
        "to-a",
        vec![ResourceChange::ReplaceMutable {
            previous: hash(&b),
            record: a,
        }],
        vec![],
    )
    .await;
    tick(&f);
    assert!(paths(&value(&f, &query("A", Some(cutoff), "")).await).is_empty());
    assert_eq!(
        paths(&value(&f, &query("A", None, "")).await),
        vec![vec![EDGE]]
    );
    tag("P3-S002");
    f.shutdown().await;
}
#[tokio::test]
async fn required_origin_denied_before_seed_cap() {
    let mut b = base();
    b.resource(entity("https://s/0-denied", "A"));
    let f = NativeFixture::new(b, reader_policy(), 1).await;
    let snap = f
        .backend
        .open_snapshot(&f.backend.head().await.unwrap())
        .await
        .unwrap();
    let key = ExportRecord::Resource(entity("https://s/0-denied", "A")).identity_key();
    let mut cursor = None;
    let mut origins = vec![];
    loop {
        let page = snap
            .export(cursor.as_ref(), PageSize::new(1).unwrap())
            .await
            .unwrap();
        for r in page.items() {
            if let ExportRecord::Resource(r) = r {
                if let Some(o) = RecordOrigin::from_resource(r, Limits::default()).unwrap() {
                    if o.key() == key {
                        origins.push(o);
                    }
                }
            }
        }
        cursor = page.next().cloned();
        if cursor.is_none() {
            break;
        }
    }
    let origin = origins
        .into_iter()
        .max_by_key(RecordOrigin::sequence)
        .unwrap()
        .id()
        .unwrap();
    tick(&f);
    assert!(
        paths(&value(&f, &query("A", None, "")).await).is_empty(),
        "lexically first allowed seed consumes cap before denial"
    );
    deny(&f, origin.as_str(), "deny-origin").await;
    let v = value(&f, &query("A", None, "")).await;
    assert_eq!(paths(&v), vec![vec![EDGE]]);
    assert!(
        !String::from_utf8(v.canonical_bytes(Limits::default()).unwrap())
            .unwrap()
            .contains("https://s/0-denied")
    );
    tag("P3-S003");
    drop(snap);
    f.shutdown().await;
}
#[tokio::test]
async fn appended_full_lifecycle_and_denied_support_never_active_fallback() {
    let mut b = base();
    b.resource(
        DependencyRecord::new(
            "ctxql-resource/v1",
            ResourceId::new("https://s/event").unwrap(),
            ResourceKind::LifecycleEvent,
            vec![Fact::new(
                property_iri("event").unwrap(),
                FactTerm::Reference(ResourceId::new(B).unwrap()),
            )],
        )
        .unwrap(),
    );
    let f = NativeFixture::new(b, reader_policy(), 1).await;
    let support=LifecycleAssertion::from_value(&V::parse(br#"{"claim_id":"https://s/retract","subject_id":"https://s/edge","relation":"ctxql:retracted_by","object_id":"https://s/event","relation_type":"https://s/Relation","subject_type":"https://s/Claim","object_type":"https://s/Event","claim_type":"https://s/Assertion","confidence":0.7,"grounding_level":"claim_only","ext":{"reason":"native appended support"}}"#,Limits::default()).unwrap()).unwrap();
    admit(&f, "retract", vec![], vec![support]).await;
    tick(&f);
    let v = value(&f, &query("A", None, "")).await;
    assert_eq!(paths(&v), vec![vec![EDGE]]);
    assert_eq!(
        v.field("claims").unwrap().as_array().unwrap()[0]
            .field("meta")
            .unwrap()
            .field("lifecycle_state")
            .unwrap(),
        &V::string("retracted")
    );
    assert_eq!(
        v.field("explain")
            .unwrap()
            .field("lifecycle")
            .unwrap()
            .as_array()
            .unwrap()[0]
            .field("supporting_ids")
            .unwrap(),
        &V::Array(vec![V::string("https://s/retract")])
    );
    deny(&f, "https://s/retract", "deny-support").await;
    for predicate in ["", r#"["meta:lifecycle_state","=","active"]"#] {
        let v = value(&f, &query("A", None, predicate)).await;
        assert!(paths(&v).is_empty());
        assert_eq!(v.field("claims").unwrap(), &V::Array(vec![]));
        assert_eq!(
            v.field("explain").unwrap().field("lifecycle").unwrap(),
            &V::Array(vec![])
        );
    }
    tag("P3-S004");
    f.shutdown().await;
}
#[tokio::test]
async fn explicit_stale_reports_actual_and_fixed_cutoff() {
    let f = NativeFixture::new(base(), reader_policy(), 1).await;
    tick(&f);
    let p = Stale {
        f: &f,
        old: f.backend.head().await.unwrap(),
        requested: Mutex::new(None),
    };
    let q = query("A", None, "").replace("\"explain\":true", "\"explain\":false");
    let (r, b) = run(&f, &p, &q, true, ExecutionOptions::default()).await;
    r.unwrap();
    let v = V::parse(&b, Limits::default()).unwrap();
    let c = v.field("consistency").unwrap();
    let requested = p.requested.lock().unwrap().clone().unwrap();
    assert_ne!(requested.snapshot, p.old);
    assert_eq!(
        c.field("actual").unwrap().field("pin").unwrap(),
        &p.old.pin().projection()
    );
    assert_eq!(
        c.field("actual").unwrap().field("backend").unwrap(),
        &V::string(p.old.backend().as_str())
    );
    assert_eq!(
        c.field("requested").unwrap().field("pin").unwrap(),
        &requested.snapshot.pin().projection()
    );
    assert_eq!(
        c.field("as_of").unwrap(),
        &V::string(requested.as_of.canonical())
    );
    assert_eq!(c.field("stale").unwrap(), &V::Bool(true));
    assert_eq!(
        v.field("semantic_flags").unwrap(),
        &V::Array(vec![V::string("stale_snapshot")])
    );
    assert_eq!(
        v.field("status").unwrap(),
        &V::string("ready_with_warnings")
    );
    assert_eq!(paths(&v), vec![vec![EDGE]]);
    tag("P3-S005");
    drop(p);
    f.shutdown().await;
}
#[tokio::test]
async fn stale_missing_artifact_does_not_fetch_latest() {
    let mut f = NativeFixture::new(base(), reader_policy(), 1).await;
    let old = f.backend.head().await.unwrap();
    f.config = artifact("https://s/new-config", CONFIG.as_bytes()).unwrap();
    ArtifactRepository::publish(f.backend.as_ref(), &f.config)
        .await
        .unwrap();
    tick(&f);
    let p = Stale {
        f: &f,
        old,
        requested: Mutex::new(None),
    };
    let (r, b) = run(
        &f,
        &p,
        &query("A", None, ""),
        true,
        ExecutionOptions::default(),
    )
    .await;
    assert_eq!(r.unwrap_err().kind, ErrorKind::NotFound);
    assert!(b.is_empty());
    tag("P3-S006");
    drop(p);
    f.shutdown().await;
}
#[tokio::test]
async fn old_graph_current_revocation_releases_nothing() {
    let f = NativeFixture::new(base(), reader_policy(), 1).await;
    let old = f.backend.head().await.unwrap();
    let mut state = f.backend.policy_state().await.unwrap();
    state
        .principals
        .get_mut(&PrincipalId::new("reader").unwrap())
        .unwrap()
        .0 = false;
    f.backend
        .set_policy_state(&IdempotencyKey::new("revoke").unwrap(), &state)
        .await
        .unwrap();
    tick(&f);
    let p = Stale {
        f: &f,
        old,
        requested: Mutex::new(None),
    };
    let (r, b) = run(
        &f,
        &p,
        &query("A", None, ""),
        true,
        ExecutionOptions::default(),
    )
    .await;
    assert_eq!(r.unwrap_err().kind, ErrorKind::Denied);
    assert!(b.is_empty());
    tag("P3-S007");
    drop(p);
    f.shutdown().await;
}
#[tokio::test]
async fn default_exact_deadline_and_cancellation_release_nothing() {
    let f = NativeFixture::new(base(), reader_policy(), 1).await;
    tick(&f);
    for options in [
        ExecutionOptions {
            deadline: Some(std::time::Instant::now()),
            ..Default::default()
        },
        ExecutionOptions {
            cancellation: Some(Arc::new(AtomicBool::new(true))),
            ..Default::default()
        },
    ] {
        let captured = f.backend.capture(None).await.unwrap();
        let error = f
            .provider
            .open(&captured, &options)
            .await
            .err()
            .expect("real provider rejects interruption");
        assert_eq!(error.kind, ErrorKind::Deadline);
        let (r, b) = run(&f, &f.provider, &query("A", None, ""), false, options).await;
        assert_eq!(r.unwrap_err().kind, ErrorKind::Deadline);
        assert!(b.is_empty());
    }
    tag("P3-S008");
    f.shutdown().await;
}
