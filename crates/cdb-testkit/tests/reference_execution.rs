use cdb_core::contracts::{GraphBackend, IoFuture, PolicyService};
use cdb_core::{
    admission::*, claim::*, id::*, policy::PolicySet, CanonicalValue as V, ErrorKind, Limits,
    Result,
};
use cdb_engine::{
    compiler::{compile, QuerySource},
    execution::{execute, property_iri, ExecutionOptions},
    options::CompileOptions,
};
use cdb_testkit::memory::{MemoryBackend, MemoryContext, MemoryPrincipal};
use cdb_testkit::reference_fixture::*;
struct NoReadProvider<'a> {
    fixture: &'a ReferenceFixture,
    reads: std::sync::atomic::AtomicUsize,
}
impl cdb_core::contracts::SourceReader for NoReadProvider<'_> {
    fn read<'a>(
        &'a self,
        _request: &'a cdb_core::source::SourceReadRequest,
    ) -> IoFuture<'a, cdb_core::source::SourceRead> {
        Box::pin(async move {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(cdb_core::Error::new(
                ErrorKind::Backend,
                "unexpected source read",
            ))
        })
    }
    fn read_reference<'a>(
        &'a self,
        _source: &'a cdb_core::evidence::SourceReference,
        _max_bytes: usize,
    ) -> IoFuture<'a, cdb_core::source::SourceRead> {
        Box::pin(async move {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(cdb_core::Error::new(
                ErrorKind::Backend,
                "unexpected source read",
            ))
        })
    }
}
impl cdb_engine::execution::ViewProvider for NoReadProvider<'_> {
    fn evidence_reader(&self) -> Option<&dyn cdb_core::contracts::SourceReader> {
        Some(self)
    }
    fn open<'a>(
        &'a self,
        captured: &'a cdb_core::contracts::CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, cdb_engine::execution::PreparedView> {
        cdb_engine::execution::ViewProvider::open(self.fixture, captured, options)
    }
}
struct MutationAtPublish<'a>(&'a MemoryBackend);
impl PolicyService for MutationAtPublish<'_> {
    type Principal = MemoryPrincipal;
    type Context = MemoryContext;
    fn current<'a>(&'a self, p: &'a MemoryPrincipal) -> IoFuture<'a, MemoryContext> {
        self.0.current(p)
    }
    fn resource_allowed(&self, c: &MemoryContext, r: &ResourceId) -> Result<bool> {
        self.0.resource_allowed(c, r)
    }
    fn fact_allowed(&self, c: &MemoryContext, r: &ResourceId, p: &Iri) -> Result<bool> {
        self.0.fact_allowed(c, r, p)
    }
    fn publish<'a>(
        &'a self,
        p: &'a MemoryPrincipal,
        c: &'a MemoryContext,
        sink: &'a mut (dyn FnMut() -> Result<()> + Send),
    ) -> IoFuture<'a, ()> {
        Box::pin(async move {
            self.0.set_policy(allow_policy()?)?;
            self.0.publish(p, c, sink).await
        })
    }
}
#[tokio::test]
async fn mutation_between_execution_and_publish_blocks_every_byte() {
    let f = fixture().await;
    let d = compile(
        QuerySource::inline(query("").as_bytes()),
        None,
        &f.config,
        CompileOptions::default(),
    )
    .unwrap();
    let mut released = false;
    let e = execute(
        d,
        &f.backend,
        &MutationAtPublish(&f.backend),
        &f.principal,
        &f,
        ExecutionOptions::default(),
        &mut |_| {
            released = true;
            Ok(())
        },
    )
    .await
    .unwrap_err();
    assert_eq!(e.kind, ErrorKind::PolicyChanged);
    assert!(!released);
}
#[tokio::test]
async fn foreign_principal_cannot_release() {
    let f = fixture().await;
    let foreign = fixture().await;
    let d = compile(
        QuerySource::inline(query("").as_bytes()),
        None,
        &f.config,
        CompileOptions::default(),
    )
    .unwrap();
    let mut released = false;
    assert!(execute(
        d,
        &f.backend,
        &f.backend,
        &foreign.principal,
        &f,
        ExecutionOptions::default(),
        &mut |_| {
            released = true;
            Ok(())
        }
    )
    .await
    .is_err());
    assert!(!released);
}
fn deny(f: &ReferenceFixture, property: bool, target: &str) {
    let mut p = allow_policy()
        .unwrap()
        .projection()
        .as_object()
        .unwrap()
        .clone();
    let mut rules = p.get("policies").unwrap().as_array().unwrap().to_vec();
    let key = if property { "onProperty" } else { "onSubject" };
    let value = format!(
        r#"{{"@id":"https://fixture.example/deny","@type":["https://ns.flur.ee/db#AccessPolicy","https://fixture.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":false,"https://ns.flur.ee/db#{key}":"{target}"}}"#
    );
    rules.push(V::parse(value.as_bytes(), Limits::default()).unwrap());
    p.insert("policies".into(), V::Array(rules));
    f.backend
        .set_policy(PolicySet::from_value(&V::Object(p)).unwrap())
        .unwrap();
}
#[tokio::test]
async fn all_metadata_guarded_even_when_unselected() {
    let f = fixture().await;
    deny(&f, true, property_iri("lineage.schema").unwrap().as_str());
    let v = run(&f, &query("")).await.unwrap();
    assert!(paths(&v).is_empty());
    assert_eq!(
        v.field("explain")
            .unwrap()
            .field("traversal_stats")
            .unwrap()
            .field("examined")
            .unwrap(),
        &V::integer(0)
    );
}
#[tokio::test]
async fn confidence_candidate_order_and_filter_before_global_path_cap() {
    let mut b = FixtureBuilder::new();
    for id in ["A", "B", "C"] {
        b.entity(&format!("https://e/{id}"), Some(id)).unwrap();
    }
    b.edge("https://e/low", "https://e/A", entity("https://e/B"), "0.2")
        .unwrap();
    b.edge(
        "https://e/high",
        "https://e/A",
        entity("https://e/C"),
        "0.9",
    )
    .unwrap();
    let f = b.build().await.unwrap();
    let v = run(
        &f,
        r#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1,"fanout_limit":1}}"#,
    )
    .await
    .unwrap();
    assert_eq!(paths(&v), vec![vec!["https://e/high"]]);
    let v=run(&f,r#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1,"path_limit":1},"filter":{"predicates":[["meta:confidence","<",0.5]]}}"#).await.unwrap();
    assert_eq!(paths(&v), vec![vec!["https://e/low"]]);
}
#[tokio::test]
async fn exact_id_label_union_and_denial_before_seed_cap() {
    let mut b = FixtureBuilder::new();
    for (id, label) in [
        ("https://e/A", "https://e/B"),
        ("https://e/B", "B"),
        ("https://e/C", "C"),
    ] {
        b.entity(id, Some(label)).unwrap();
    }
    b.edge("https://e/a", "https://e/A", entity("https://e/C"), "1")
        .unwrap();
    b.edge("https://e/b", "https://e/B", entity("https://e/C"), "1")
        .unwrap();
    let f = b.build().await.unwrap();
    let q = r#"{"about":[{"from":["https://e/B"],"match":"exact"}],"bounds":{"max_depth":1,"seed_limit":1}}"#;
    assert_eq!(paths(&run(&f, q).await.unwrap()), vec![vec!["https://e/a"]]);
    deny(&f, false, "https://e/A");
    assert_eq!(paths(&run(&f, q).await.unwrap()), vec![vec!["https://e/b"]]);
}
#[tokio::test]
async fn all_cycle_policies_and_reused_global_claim_budget() {
    for (cycle, expected) in [
        ("no_repeated_claim", 1),
        ("allow_repeated_claim", 3),
        ("no_repeated_node", 0),
    ] {
        let mut b = FixtureBuilder::new();
        b.entity("https://e/A", Some("A")).unwrap();
        b.edge("https://e/loop", "https://e/A", entity("https://e/A"), "1")
            .unwrap();
        let mut f = b.build().await.unwrap();
        let config = artifact(
            "https://fixture.example/cycle-config",
            CONFIG.replace("no_repeated_claim", cycle).as_bytes(),
        )
        .unwrap();
        let batch = AdmissionBatch::new(
            vec![],
            vec![],
            vec![],
            vec![config.clone()],
            V::Object(Default::default()),
            Limits::default(),
        )
        .unwrap();
        f.backend
            .admit(&IdempotencyKey::new("cycle-config").unwrap(), &batch)
            .await
            .unwrap();
        f.config = config;
        let q =
            r#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":3,"max_claims":1}}"#;
        assert_eq!(paths(&run(&f, q).await.unwrap()).len(), expected, "{cycle}");
    }
}
#[tokio::test]
async fn complete_small_pages_before_semantic_order() {
    let mut b = FixtureBuilder::new();
    for id in ["A", "B", "C"] {
        b.entity(&format!("https://e/{id}"), Some(id)).unwrap();
    }
    b.edge(
        "https://e/a-low",
        "https://e/A",
        entity("https://e/B"),
        "0.1",
    )
    .unwrap();
    b.edge(
        "https://e/z-high",
        "https://e/A",
        entity("https://e/C"),
        "0.9",
    )
    .unwrap();
    let f = b.build().await.unwrap();
    let q =
        r#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1,"fanout_limit":1}}"#;
    let d = compile(
        QuerySource::inline(q.as_bytes()),
        None,
        &f.config,
        CompileOptions::default(),
    )
    .unwrap();
    let mut bytes = vec![];
    execute(
        d,
        &f.backend,
        &f.backend,
        &f.principal,
        &f,
        ExecutionOptions {
            page_size: cdb_core::snapshot::PageSize::new(1).unwrap(),
            ..ExecutionOptions::default()
        },
        &mut |b| {
            bytes.extend_from_slice(b);
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(
        paths(&V::parse(&bytes, Limits::default()).unwrap()),
        vec![vec!["https://e/z-high"]]
    );
}
fn entity(id: &str) -> ClaimObject {
    ClaimObject::Entity(EntityId::new(id).unwrap())
}
async fn fixture() -> ReferenceFixture {
    let mut b = FixtureBuilder::new();
    for id in ["https://e/A", "https://e/B", "https://e/C"] {
        b.entity(id, Some(id.rsplit('/').next().unwrap())).unwrap();
    }
    b.edge("https://e/c1", "https://e/A", entity("https://e/B"), "0.5")
        .unwrap();
    b.edge("https://e/c2", "https://e/B", entity("https://e/C"), "0.8")
        .unwrap();
    b.build().await.unwrap()
}
async fn run(f: &ReferenceFixture, q: &str) -> Result<V> {
    let d = compile(
        QuerySource::inline(q.as_bytes()),
        None,
        &f.config,
        CompileOptions::default(),
    )?;
    let mut bytes = vec![];
    execute(
        d,
        &f.backend,
        &f.backend,
        &f.principal,
        f,
        ExecutionOptions::default(),
        &mut |b| {
            bytes.extend_from_slice(b);
            Ok(())
        },
    )
    .await?;
    V::parse(&bytes, Limits::default())
}
fn query(extra: &str) -> String {
    format!(
        r#"{{"about":[{{"from":["A"],"match":"exact"}}],"bounds":{{"max_depth":3}},"return":{{"explain":true}}{extra}}}"#
    )
}
fn paths(v: &V) -> Vec<Vec<String>> {
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
                .map(|v| v.as_str().unwrap().to_owned())
                .collect()
        })
        .collect()
}
#[tokio::test]
async fn historical_cutoff_excludes_fixture_label_admission() {
    let f = fixture().await;
    let q = r#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":2,"as_of":"2026-03-31T00:00:00Z"},"return":{"explain":true}}"#;
    let v = run(&f, q).await.unwrap();
    assert!(paths(&v).is_empty());
    assert_eq!(
        v.field("explain").unwrap().field("seeds").unwrap(),
        &V::Array(vec![])
    );
}
#[tokio::test]
async fn actual_outgoing_paths_confidence_and_hash() {
    let f = fixture().await;
    let v = run(&f, &query("")).await.unwrap();
    assert_eq!(
        paths(&v),
        vec![vec!["https://e/c1"], vec!["https://e/c1", "https://e/c2"]]
    );
    assert_eq!(
        v.field("paths").unwrap().as_array().unwrap()[1]
            .field("scores")
            .unwrap()
            .field("accumulated_confidence")
            .unwrap()
            .as_number()
            .unwrap(),
        &cdb_core::ExactNumber::parse("0.4").unwrap()
    );
    assert!(v
        .field("response_hash")
        .unwrap()
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}
#[tokio::test]
async fn incoming_preserves_stored_orientation() {
    let f = fixture().await;
    let v=run(&f,r#"{"about":[{"from":["C"],"match":"exact"}],"bounds":{"max_depth":2},"walk":{"direction":"incoming"}}"#).await.unwrap();
    assert_eq!(
        paths(&v),
        vec![vec!["https://e/c2"], vec!["https://e/c2", "https://e/c1"]]
    );
    let c = &v.field("claims").unwrap().as_array().unwrap()[0];
    assert_eq!(
        c.field("meta")
            .unwrap()
            .field("subject_id")
            .unwrap()
            .as_str()
            .unwrap(),
        "https://e/A"
    );
}
#[tokio::test]
async fn filter_is_post_walk_independently_existential() {
    let f = fixture().await;
    let v=run(&f,&query(r#", "filter":{"predicates":[["meta:confidence","=",0.5],["meta:confidence","=",0.8]]}"#)).await.unwrap();
    assert_eq!(paths(&v), vec![vec!["https://e/c1", "https://e/c2"]]);
}
#[tokio::test]
async fn semantic_zeros_and_operational_failure_never_publish() {
    let f = fixture().await;
    for cap in [
        "max_depth",
        "seed_limit",
        "fanout_limit",
        "max_claims",
        "path_limit",
    ] {
        let bounds = if cap == "max_depth" {
            "\"max_depth\":0".into()
        } else {
            format!("\"max_depth\":3,\"{cap}\":0")
        };
        let q = format!(r#"{{"about":[{{"from":["A"],"match":"exact"}}],"bounds":{{{bounds}}}}}"#);
        assert!(paths(&run(&f, &q).await.unwrap()).is_empty(), "{cap}");
    }
    let d = compile(
        QuerySource::inline(query("").as_bytes()),
        None,
        &f.config,
        CompileOptions::default(),
    )
    .unwrap();
    let mut released = false;
    let e = execute(
        d,
        &f.backend,
        &f.backend,
        &f.principal,
        &f,
        ExecutionOptions {
            max_work: 0,
            ..ExecutionOptions::default()
        },
        &mut |_| {
            released = true;
            Ok(())
        },
    )
    .await
    .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Limit);
    assert!(!released);
}
#[tokio::test]
async fn denied_bridge_and_metadata_do_not_leak() {
    let f = fixture().await;
    let policy = allow_policy().unwrap().projection();
    let mut p = policy.as_object().unwrap().clone();
    let mut rules = p.get("policies").unwrap().as_array().unwrap().to_vec();
    let deny = r#"{"@id":"https://fixture.example/deny","@type":["https://ns.flur.ee/db#AccessPolicy","https://fixture.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":false,"https://ns.flur.ee/db#onSubject":"https://e/c1"}"#;
    rules.push(V::parse(deny.as_bytes(), Limits::default()).unwrap());
    p.insert("policies".into(), V::Array(rules));
    f.backend
        .set_policy(PolicySet::from_value(&V::Object(p)).unwrap())
        .unwrap();
    let v = run(&f, &query("")).await.unwrap();
    assert!(paths(&v).is_empty());
    let bytes = v.canonical_bytes(Limits::default()).unwrap();
    assert!(!String::from_utf8(bytes).unwrap().contains("https://e/c1"));
}
#[tokio::test]
async fn literal_terminal_and_both_self_loop_once() {
    let mut b = FixtureBuilder::new();
    b.entity("https://e/A", Some("A")).unwrap();
    b.edge("https://e/loop", "https://e/A", entity("https://e/A"), "1")
        .unwrap();
    b.edge(
        "https://e/literal",
        "https://e/A",
        ClaimObject::Literal(
            TypedLiteral::new(
                Iri::new("http://www.w3.org/2001/XMLSchema#string").unwrap(),
                V::string("https://e/B"),
                None,
            )
            .unwrap(),
        ),
        "1",
    )
    .unwrap();
    let f = b.build().await.unwrap();
    let v = run(&f, &query(r#", "walk":{"direction":"both"}"#))
        .await
        .unwrap();
    assert_eq!(
        paths(&v),
        vec![
            vec!["https://e/literal"],
            vec!["https://e/loop"],
            vec!["https://e/loop", "https://e/literal"]
        ]
    );
    assert_eq!(
        v.field("paths").unwrap().as_array().unwrap()[0]
            .field("node_ids")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
#[tokio::test]
async fn lifecycle_retraction_is_not_implicit_filter() {
    let mut b = FixtureBuilder::new();
    b.entity("https://e/A", Some("A")).unwrap();
    b.entity("https://e/B", Some("B")).unwrap();
    b.edge("https://e/c1", "https://e/A", entity("https://e/B"), "1")
        .unwrap();
    b.resource(
        DependencyRecord::new(
            "ctxql-resource/v1",
            ResourceId::new("https://e/event").unwrap(),
            ResourceKind::LifecycleEvent,
            vec![Fact::new(
                property_iri("event").unwrap(),
                FactTerm::Literal(
                    TypedLiteral::new(
                        Iri::new("http://www.w3.org/2001/XMLSchema#string").unwrap(),
                        V::string("withdrawal"),
                        None,
                    )
                    .unwrap(),
                ),
            )],
        )
        .unwrap(),
    );
    let a=V::parse(br#"{"claim_id":"https://e/retraction","subject_id":"https://e/c1","relation":"ctxql:retracted_by","object_id":"https://e/event","relation_type":"https://e/Relation","subject_type":"https://e/Claim","object_type":"https://e/Event","claim_type":"https://e/Assertion","confidence":1,"grounding_level":"claim_only"}"#,Limits::default()).unwrap();
    b.lifecycle(LifecycleAssertion::from_value(&a).unwrap());
    let f = b.build().await.unwrap();
    let v = run(&f, &query("")).await.unwrap();
    assert_eq!(paths(&v), vec![vec!["https://e/c1"]]);
    assert_eq!(
        v.field("claims").unwrap().as_array().unwrap()[0]
            .field("meta")
            .unwrap()
            .field("lifecycle_state")
            .unwrap()
            .as_str()
            .unwrap(),
        "retracted"
    );
    assert_eq!(
        v.field("explain")
            .unwrap()
            .field("lifecycle")
            .unwrap()
            .as_array()
            .unwrap()[0]
            .field("supporting_ids")
            .unwrap()
            .as_array()
            .unwrap(),
        &[V::string("https://e/retraction")]
    );
    deny(&f, false, "https://e/retraction");
    let denied = run(&f, &query("")).await.unwrap();
    assert!(paths(&denied).is_empty());
    assert!(
        !String::from_utf8(denied.canonical_bytes(Limits::default()).unwrap())
            .unwrap()
            .contains("https://e/retraction")
    );
}
#[tokio::test]
async fn target_paths_continue_after_target_without_zero_hop() {
    let f = fixture().await;
    let v = run(
        &f,
        r#"{"about":[{"from":["A"],"to":["A","B","C"],"match":"exact"}],"bounds":{"max_depth":3}}"#,
    )
    .await
    .unwrap();
    assert_eq!(
        paths(&v),
        vec![vec!["https://e/c1"], vec!["https://e/c1", "https://e/c2"]]
    );
}
#[tokio::test]
async fn evidence_unavailability_is_transport_only() {
    let f = fixture().await;
    let a = run(&f, &query("")).await.unwrap();
    let q = query("").replace("\"explain\":true", "\"explain\":true,\"evidence\":true");
    let b = run(&f, &q).await.unwrap();
    assert_eq!(paths(&a), paths(&b));
    assert_eq!(
        a.field("graph_status").unwrap(),
        b.field("graph_status").unwrap()
    );
    assert_eq!(b.field("evidence").unwrap(), &V::Array(vec![]));
}
#[tokio::test]
async fn exact_fixture_hydration_does_not_change_graph_hash() {
    use cdb_testkit::sources::{ImmutableSource, ScriptedSources, SourceOptions};
    let bytes = b"secret public private";
    let version = ContentHash::of_bytes(bytes);
    let content_hash = ContentHash::of_bytes(b"public");
    let mut b = FixtureBuilder::new();
    b.entity("https://e/A", Some("A")).unwrap();
    b.entity("https://e/B", Some("B")).unwrap();
    b.resource(
        DependencyRecord::new(
            "ctxql-resource/v1",
            ResourceId::new("https://e/source").unwrap(),
            ResourceKind::SourceDescriptor,
            vec![Fact::new(
                property_iri("source.version").unwrap(),
                FactTerm::Literal(
                    TypedLiteral::new(
                        Iri::new("http://www.w3.org/2001/XMLSchema#string").unwrap(),
                        V::string(version.as_str()),
                        None,
                    )
                    .unwrap(),
                ),
            )],
        )
        .unwrap(),
    );
    let claim = format!(
        r#"{{"claim_id":"https://e/c","subject_id":"https://e/A","relation":"https://e/rel","object_id":"https://e/B","relation_type":"https://e/Relation","subject_type":"https://e/Entity","object_type":"https://e/Entity","claim_type":"https://e/Assertion","confidence":1,"grounding_level":"source_spans_available","lineage":{{"schema":"ctxql.lineage.v1","sources":[{{"source_id":"https://e/source","kind":"text","version":"{}","content_hash":"{}","selectors":{{"contract":"ctxql-evidence/v1","utf8":{{"start":7,"end":13}}}}}}]}}}}"#,
        version.as_str(),
        content_hash.as_str()
    );
    b.claim(
        CandidateClaim::from_value(&V::parse(claim.as_bytes(), Limits::default()).unwrap())
            .unwrap(),
    )
    .unwrap();
    let f = b.build().await.unwrap();
    let sources = ScriptedSources::new(
        vec![ImmutableSource::new(
            SourceId::new("https://e/source").unwrap(),
            bytes.to_vec(),
        )],
        SourceOptions::default(),
    )
    .unwrap();
    let provider = FixtureEvidence {
        fixture: &f,
        sources: &sources,
    };
    // Each capture intentionally commits a distinct data pin. Unselect explain so this
    // compares hydration, not two different captured db_time explain contexts.
    let q = query("").replace("\"explain\":true", "\"explain\":false,\"evidence\":true");
    let no_reads = NoReadProvider {
        fixture: &f,
        reads: std::sync::atomic::AtomicUsize::new(0),
    };
    let no_evidence = compile(
        QuerySource::inline(query("").as_bytes()),
        None,
        &f.config,
        CompileOptions::default(),
    )
    .unwrap();
    execute(
        no_evidence,
        &f.backend,
        &f.backend,
        &f.principal,
        &no_reads,
        ExecutionOptions::default(),
        &mut |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(no_reads.reads.load(std::sync::atomic::Ordering::SeqCst), 0);
    let unavailable = run(&f, &q).await.unwrap();
    let d = compile(
        QuerySource::inline(q.as_bytes()),
        None,
        &f.config,
        CompileOptions::default(),
    )
    .unwrap();
    let mut bytes = vec![];
    execute(
        d,
        &f.backend,
        &f.backend,
        &f.principal,
        &provider,
        ExecutionOptions::default(),
        &mut |b| {
            bytes.extend_from_slice(b);
            Ok(())
        },
    )
    .await
    .unwrap();
    let available = V::parse(&bytes, Limits::default()).unwrap();
    assert_eq!(
        unavailable.field("response_hash").unwrap(),
        available.field("response_hash").unwrap()
    );
    assert_eq!(
        available.field("evidence").unwrap().as_array().unwrap()[0]
            .field("content")
            .unwrap(),
        &V::string("public")
    );
    assert!(!String::from_utf8(bytes).unwrap().contains("secret"));
}
