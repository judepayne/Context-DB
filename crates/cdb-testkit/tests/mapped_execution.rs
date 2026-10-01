use cdb_core::{
    artifact::PublishedArtifact, claim::CandidateClaim, contracts::*, id::*, snapshot::SnapshotRef,
    CanonicalValue as V, ErrorKind, Limits, Result,
};
use cdb_engine::{compiler::*, execution::*, options::CompileOptions};
use cdb_testkit::reference_fixture::*;
use std::sync::atomic::{AtomicUsize, Ordering};
struct Local<'a> {
    fixture: &'a ReferenceFixture,
    snapshot: std::sync::OnceLock<SnapshotRef>,
    wrong_backend: bool,
    dependencies: Vec<MappingDependency>,
    value: Option<V>,
    reads: AtomicUsize,
}
impl MappedFieldProvider for Local<'_> {
    fn identity(&self) -> &SnapshotRef {
        self.snapshot.get().unwrap()
    }
    fn supports(&self, m: &StoredPredicateMapping) -> bool {
        m.iri().as_str() == "https://fixture.example/mapped"
    }
    fn dependencies(
        &self,
        _: &ClaimId,
        _: &StoredPredicateMapping,
    ) -> Result<&[MappingDependency]> {
        Ok(&self.dependencies)
    }
    fn value(&self, _: &ClaimId, _: &StoredPredicateMapping) -> Result<Option<&V>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.value.as_ref())
    }
}
impl ViewProvider for Local<'_> {
    fn mapped_fields(&self) -> Option<&dyn MappedFieldProvider> {
        Some(self)
    }
    fn open<'a>(
        &'a self,
        c: &'a CapturedSnapshot,
        o: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        self.snapshot.get_or_init(|| {
            if self.wrong_backend {
                SnapshotRef::new(
                    BackendId::new("other-backend").unwrap(),
                    c.snapshot.pin().clone(),
                )
            } else {
                c.snapshot.clone()
            }
        });
        self.fixture.open(c, o)
    }
}
async fn fixture() -> (ReferenceFixture, PublishedArtifact) {
    let config=artifact("urn:mapped-config",CONFIG.replace("\"fields\":{}",r#""fields":{"meta:ext:x":{"source":"stored_predicate","iri":"https://fixture.example/mapped"}}"#).as_bytes()).unwrap();
    let mut b = FixtureBuilder::new();
    b.artifact(config.clone());
    b.entity("urn:A", None)
        .unwrap()
        .entity("urn:B", None)
        .unwrap()
        .entity("https://fixture.example/dependency", Some("support"))
        .unwrap();
    let c=V::parse(br#"{"claim_id":"urn:c","subject_id":"urn:A","relation":"urn:edge","object_id":"urn:B","relation_type":"urn:Relation","subject_type":"urn:Entity","object_type":"urn:Entity","claim_type":"urn:Assertion","confidence":1,"grounding_level":"claim_only","ext":{"x":"stored"}}"#,Limits::default()).unwrap();
    b.claim(CandidateClaim::from_value(&c).unwrap()).unwrap();
    (b.build().await.unwrap(), config)
}
fn draft(c: &PublishedArtifact, op: &str, value: &str) -> ValidatedDraft {
    let q = format!(
        r#"{{"about":[{{"from":["urn:A"],"match":"exact"}}],"bounds":{{"max_depth":1}},"walk":{{"predicates":[["meta:ext:x","{op}",{value}]]}}}}"#
    );
    compile_with_capabilities(
        QuerySource::inline(q.as_bytes()),
        None,
        c,
        CompileOptions::default(),
        MappingCapabilities {
            stored_predicate: true,
            ..MappingCapabilities::default()
        },
    )
    .unwrap()
}
async fn run(
    f: &ReferenceFixture,
    p: &dyn ViewProvider,
    d: ValidatedDraft,
) -> (Result<()>, Vec<u8>) {
    let mut bytes = vec![];
    let result = execute(
        d,
        &f.backend,
        &f.backend,
        &f.principal,
        p,
        ExecutionOptions::default(),
        &mut |b| {
            bytes.extend_from_slice(b);
            Ok(())
        },
    )
    .await;
    (result, bytes)
}
async fn local(f: &ReferenceFixture, value: Option<V>) -> Local<'_> {
    Local {
        fixture: f,
        snapshot: std::sync::OnceLock::new(),
        wrong_backend: false,
        dependencies: vec![MappingDependency {
            resource: ResourceId::new("https://fixture.example/dependency").unwrap(),
            facts: vec![property_iri("label").unwrap()],
        }],
        value,
        reads: AtomicUsize::new(0),
    }
}
#[tokio::test]
async fn provider_absence_and_wrong_full_snapshot_release_nothing() {
    let (f, c) = fixture().await;
    let (r, b) = run(&f, &f, draft(&c, "=", r#""mapped""#)).await;
    assert_eq!(r.unwrap_err().kind, ErrorKind::Unsupported);
    assert!(b.is_empty());
    let mut p = local(&f, Some(V::string("mapped"))).await;
    p.wrong_backend = true;
    let (r, b) = run(&f, &p, draft(&c, "=", r#""mapped""#)).await;
    assert_eq!(r.unwrap_err().kind, ErrorKind::Snapshot);
    assert!(b.is_empty());
    assert_eq!(p.reads.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn mapped_overrides_stored_and_missing_is_not_fallback() {
    let (f, c) = fixture().await;
    for (value, op, operand, count) in [
        (Some(V::string("mapped")), "=", r#""mapped""#, 1),
        (Some(V::string("mapped")), "=", r#""stored""#, 0),
        (None, "exists", "false", 1),
        (None, "=", r#""stored""#, 0),
    ] {
        let p = local(&f, value).await;
        let (r, b) = run(&f, &p, draft(&c, op, operand)).await;
        r.unwrap();
        let response = V::parse(&b, Limits::default()).unwrap();
        assert_eq!(
            response.field("paths").unwrap().as_array().unwrap().len(),
            count
        );
        assert!(p.reads.load(Ordering::SeqCst) > 0);
    }
}
#[tokio::test]
async fn denied_fact_blocks_before_value_resolution() {
    let (f, c) = fixture().await;
    let mut policy = allow_policy()
        .unwrap()
        .projection()
        .as_object()
        .unwrap()
        .clone();
    let mut rules = policy["policies"].as_array().unwrap().to_vec();
    let deny = format!(
        r#"{{"@id":"https://fixture.example/deny","@type":["https://ns.flur.ee/db#AccessPolicy","https://fixture.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":false,"https://ns.flur.ee/db#onProperty":"{}"}}"#,
        property_iri("label").unwrap().as_str()
    );
    rules.push(V::parse(deny.as_bytes(), Limits::default()).unwrap());
    policy.insert("policies".into(), V::Array(rules));
    f.backend
        .set_policy(cdb_core::policy::PolicySet::from_value(&V::Object(policy)).unwrap())
        .unwrap();
    let p = local(&f, Some(V::string("hidden-sentinel"))).await;
    let (r, b) = run(&f, &p, draft(&c, "=", r#""stored""#)).await;
    assert_eq!(r.unwrap_err().kind, ErrorKind::Denied);
    assert!(b.is_empty());
    assert_eq!(p.reads.load(Ordering::SeqCst), 0);
}
