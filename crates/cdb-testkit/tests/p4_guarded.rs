//! Focused memory guard regressions, not native/service capability certification.
use cdb_core::{
    admission::{DependencyRecord, Fact, FactTerm, ResourceKind},
    artifact::PublishedArtifact,
    claim::{ClaimObject, TypedLiteral},
    contracts::{IoFuture, PolicyService},
    id::{EntityId, Iri, ResourceId},
    recording::REQUIRED_SCOPES,
    CanonicalValue as V, ErrorKind, Result,
};
use cdb_engine::{
    compiler::{compile, QuerySource},
    execution::{execute, prepare_recorded, ExecutionOptions},
    options::CompileOptions,
};
use cdb_testkit::{
    memory::{MemoryBackend, MemoryContext, MemoryPrincipal},
    reference_fixture::{artifact, FixtureBuilder, ReferenceFixture},
};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const QUERY: &str = r#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1}}"#;

async fn fixture(run_interpretation: bool) -> (ReferenceFixture, PublishedArtifact) {
    let mut b = FixtureBuilder::new();
    b.entity("https://e/A", Some("A")).unwrap();
    b.entity("https://e/B", Some("B")).unwrap();
    b.edge(
        "https://e/ab",
        "https://e/A",
        ClaimObject::Entity(EntityId::new("https://e/B").unwrap()),
        "0.8",
    )
    .unwrap();
    for id in REQUIRED_SCOPES {
        b.resource(record(id, ResourceKind::SourceDescriptor));
    }
    if run_interpretation {
        b.resource(record(
            "https://fixture.example/Relation",
            ResourceKind::RunDescriptor,
        ));
    }
    let q = artifact("https://e/query", QUERY.as_bytes()).unwrap();
    b.artifact(q.clone());
    (b.build().await.unwrap(), q)
}
fn record(id: &str, kind: ResourceKind) -> DependencyRecord {
    DependencyRecord::new(
        "ctxql-resource/v1",
        ResourceId::new(id).unwrap(),
        kind,
        vec![Fact::new(
            Iri::new("https://e/value").unwrap(),
            FactTerm::Literal(
                TypedLiteral::new(
                    Iri::new("http://www.w3.org/2001/XMLSchema#string").unwrap(),
                    V::string("protected-run-sentinel"),
                    None,
                )
                .unwrap(),
            ),
        )],
    )
    .unwrap()
}

enum Interrupt {
    Cancel(Arc<AtomicBool>),
    Deadline(Instant),
}
struct AtPublish<'a> {
    backend: &'a MemoryBackend,
    reached: AtomicUsize,
    inner: AtomicUsize,
    interrupt: Interrupt,
}
impl PolicyService for AtPublish<'_> {
    type Principal = MemoryPrincipal;
    type Context = MemoryContext;
    fn current<'a>(&'a self, p: &'a MemoryPrincipal) -> IoFuture<'a, MemoryContext> {
        self.backend.current(p)
    }
    fn resource_allowed(&self, c: &MemoryContext, r: &ResourceId) -> Result<bool> {
        self.backend.resource_allowed(c, r)
    }
    fn fact_allowed(&self, c: &MemoryContext, r: &ResourceId, p: &Iri) -> Result<bool> {
        self.backend.fact_allowed(c, r, p)
    }
    fn publish<'a>(
        &'a self,
        p: &'a MemoryPrincipal,
        c: &'a MemoryContext,
        sink: &'a mut (dyn FnMut() -> Result<()> + Send),
    ) -> IoFuture<'a, ()> {
        Box::pin(async move {
            self.reached.fetch_add(1, Ordering::SeqCst);
            match &self.interrupt {
                Interrupt::Cancel(flag) => {
                    assert!(
                        !flag.swap(true, Ordering::SeqCst),
                        "cancellation preceded publication"
                    );
                }
                Interrupt::Deadline(deadline) => {
                    assert!(
                        Instant::now() < *deadline,
                        "deadline expired before publication wait"
                    );
                    // Model waiting for the authority gate, then actually invoke the engine callback.
                    tokio::time::sleep_until(tokio::time::Instant::from_std(*deadline)).await;
                    assert!(Instant::now() >= *deadline);
                }
            }
            self.backend
                .publish(p, c, &mut || {
                    self.inner.fetch_add(1, Ordering::SeqCst);
                    sink()
                })
                .await
        })
    }
}
async fn interrupted(cancel: bool) {
    let (f, _) = fixture(false).await;
    let flag = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + Duration::from_secs(1);
    let policy = AtPublish {
        backend: &f.backend,
        reached: AtomicUsize::new(0),
        inner: AtomicUsize::new(0),
        interrupt: if cancel {
            Interrupt::Cancel(flag.clone())
        } else {
            Interrupt::Deadline(deadline)
        },
    };
    let options = ExecutionOptions {
        cancellation: cancel.then_some(flag),
        deadline: (!cancel).then_some(deadline),
        ..ExecutionOptions::default()
    };
    let draft = compile(
        QuerySource::inline(QUERY.as_bytes()),
        None,
        &f.config,
        CompileOptions::default(),
    )
    .unwrap();
    let mut calls = 0;
    let mut bytes = Vec::new();
    let error = tokio::time::timeout(
        Duration::from_secs(3),
        execute(
            draft,
            &f.backend,
            &policy,
            &f.principal,
            &f,
            options,
            &mut |body| {
                calls += 1;
                bytes.extend_from_slice(body);
                Ok(())
            },
        ),
    )
    .await
    .expect("bounded publication wait")
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Deadline);
    assert_eq!(policy.reached.load(Ordering::SeqCst), 1);
    assert_eq!(policy.inner.load(Ordering::SeqCst), 1);
    assert_eq!(calls, 0);
    assert!(bytes.is_empty());
}
#[tokio::test]
async fn cancellation_only_at_publish_entry_releases_nothing() {
    interrupted(true).await;
    println!("P4_CASE {{\"id\":\"P4-G001\",\"outcome\":\"passed\"}}");
}
#[tokio::test]
async fn deadline_expires_during_publish_wait_releases_nothing() {
    interrupted(false).await;
    println!("P4_CASE {{\"id\":\"P4-G002\",\"outcome\":\"passed\"}}");
}

#[tokio::test]
async fn recording_trace_budget_rejects_before_pending_result() {
    let (f, q) = fixture(false).await;
    let draft = || {
        compile(
            QuerySource::published(&q),
            None,
            &f.config,
            CompileOptions::default(),
        )
        .unwrap()
    };
    let full = prepare_recorded(
        draft(),
        &f.backend,
        &f.backend,
        &f.principal,
        &f,
        None,
        ExecutionOptions::default(),
    )
    .await
    .unwrap();
    assert!(full.data().data().reads.len() > 10);
    assert!(!full.data().data().policy.is_empty());
    // Each top-level footprint collection fits independently, but their combined
    // footprint must fit before the core constructor can return validated data.
    let input = full.data().data();
    let counts = [
        input.landings.len(),
        input.catalog.len(),
        input.policy.len(),
        input.reads.len(),
        input.scopes.len(),
        input.functions.len(),
    ];
    let ceiling = counts.iter().sum::<usize>() - 1;
    assert!(counts.iter().all(|count| *count < ceiling));
    let limits = cdb_core::Limits::default();
    let low = cdb_core::Limits::new(
        limits.input_bytes(),
        limits.depth(),
        ceiling,
        limits.work(),
        limits.output_bytes(),
    )
    .unwrap();
    assert_eq!(
        cdb_core::recording::ReplayData::new(input.clone(), low)
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
    // Ordinary execution fits this record ceiling; complete recording must not silently truncate.
    let options = ExecutionOptions {
        max_records: 32,
        ..ExecutionOptions::default()
    };
    let mut ordinary_calls = 0;
    execute(
        draft(),
        &f.backend,
        &f.backend,
        &f.principal,
        &f,
        options.clone(),
        &mut |_| {
            ordinary_calls += 1;
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(ordinary_calls, 1);
    let result = prepare_recorded(
        draft(),
        &f.backend,
        &f.backend,
        &f.principal,
        &f,
        None,
        options,
    )
    .await;
    assert!(matches!(result, Err(e) if e.kind == ErrorKind::Limit));
    println!("P4_CASE {{\"id\":\"P4-G003\",\"outcome\":\"passed\"}}");
}

#[tokio::test]
async fn run_descriptor_cannot_supply_claim_interpretation() {
    for blocked in [false, true] {
        let (f, _) = fixture(blocked).await;
        let draft = compile(
            QuerySource::inline(QUERY.as_bytes()),
            None,
            &f.config,
            CompileOptions::default(),
        )
        .unwrap();
        let mut body = Vec::new();
        execute(
            draft,
            &f.backend,
            &f.backend,
            &f.principal,
            &f,
            ExecutionOptions::default(),
            &mut |bytes| {
                body.extend_from_slice(bytes);
                Ok(())
            },
        )
        .await
        .unwrap();
        let value = V::parse(&body, cdb_core::Limits::default()).unwrap();
        assert_eq!(
            value.field("paths").unwrap().as_array().unwrap().is_empty(),
            blocked
        );
        assert!(!String::from_utf8(body)
            .unwrap()
            .contains("protected-run-sentinel"));
    }
    println!("P4_CASE {{\"id\":\"P4-G004\",\"outcome\":\"passed\"}}");
}
