//! Instrumented memory integration, not native/authenticated capability certification.
use cdb_core::{
    admission::*, artifact::*, claim::*, contracts::*, id::*, policy::PolicySet, recording::*,
    replay::ReplayVerdict, snapshot::*, CanonicalValue as V, Error, ErrorKind, Limits, Result,
    Timestamp,
};
use cdb_engine::{
    compiler::{compile, QuerySource, ValidatedDraft},
    execution::*,
    options::CompileOptions,
};
use cdb_testkit::{memory::MemoryBackend, reference_fixture::*};
use std::sync::Arc;

fn query(anchor: &str, explain: bool) -> String {
    format!(
        r#"{{"about":[{{"from":["{anchor}"],"match":"exact"}}],"bounds":{{"max_depth":1}},"return":{{"explain":{explain}}}}}"#
    )
}
fn entity(id: &str) -> ClaimObject {
    ClaimObject::Entity(EntityId::new(id).unwrap())
}
async fn setup(text: &str) -> (ReferenceFixture, PublishedArtifact) {
    let mut b = FixtureBuilder::new();
    for id in ["A", "B", "C"] {
        b.entity(&format!("https://e/{id}"), Some(id)).unwrap();
    }
    b.edge("https://e/ab", "https://e/A", entity("https://e/B"), "0.8")
        .unwrap();
    b.edge("https://e/ac", "https://e/A", entity("https://e/C"), "0.7")
        .unwrap();
    for scope in REQUIRED_SCOPES {
        b.resource(
            DependencyRecord::new(
                "ctxql-resource/v1",
                ResourceId::new(scope).unwrap(),
                ResourceKind::SourceDescriptor,
                vec![Fact::new(
                    Iri::new("https://e/scope-kind").unwrap(),
                    FactTerm::Literal(
                        TypedLiteral::new(
                            Iri::new("http://www.w3.org/2001/XMLSchema#string").unwrap(),
                            V::string("complete"),
                            None,
                        )
                        .unwrap(),
                    ),
                )],
            )
            .unwrap(),
        );
    }
    let q = artifact("https://e/query", text.as_bytes()).unwrap();
    b.artifact(q.clone());
    (b.build().await.unwrap(), q)
}
fn draft(f: &ReferenceFixture, q: &PublishedArtifact) -> ValidatedDraft {
    compile(
        QuerySource::published(q),
        None,
        &f.config,
        CompileOptions::default(),
    )
    .unwrap()
}
struct Catalog {
    pin: SnapshotRef,
    entries: Vec<LandingEntry>,
    panic_entries: bool,
}
impl LandingCatalog for Catalog {
    fn identity(&self) -> &SnapshotRef {
        &self.pin
    }
    fn entries(&self) -> &[LandingEntry] {
        assert!(!self.panic_entries, "replay landing resolver invoked");
        &self.entries
    }
}
// Explicitly registered simple catalog, one complete entity+label entry per identity.
// Standard catalogs have identity-only and alias entries; current core codec blocks those.
struct Provider<'a> {
    f: &'a ReferenceFixture,
    replay: bool,
    missing: bool,
}
impl ViewProvider for Provider<'_> {
    fn open<'a>(
        &'a self,
        c: &'a CapturedSnapshot,
        o: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        Box::pin(async move {
            if self.missing {
                return Err(Error::new(ErrorKind::Snapshot, "missing pin"));
            }
            let p = self.f.open(c, o).await?;
            let entries = if self.replay {
                vec![]
            } else {
                p.landing
                    .entries()
                    .iter()
                    .filter(|e| e.label.is_some())
                    .cloned()
                    .collect()
            };
            Ok(PreparedView {
                view: p.view,
                landing: Arc::new(Catalog {
                    pin: c.snapshot.clone(),
                    entries,
                    panic_entries: self.replay,
                }),
            })
        })
    }
}
struct NoCapture<'a>(&'a MemoryBackend);
impl GraphBackend for NoCapture<'_> {
    fn capabilities(&self) -> Result<BackendCapabilities> {
        self.0.capabilities()
    }
    fn head(&self) -> IoFuture<'_, SnapshotRef> {
        self.0.head()
    }
    fn admit<'a>(
        &'a self,
        k: &'a IdempotencyKey,
        b: &'a AdmissionBatch,
    ) -> IoFuture<'a, AdmissionReceipt> {
        self.0.admit(k, b)
    }
    fn receipt<'a>(&'a self, k: &'a IdempotencyKey) -> IoFuture<'a, Option<AdmissionReceipt>> {
        self.0.receipt(k)
    }
    fn capture(&self, _: Option<Timestamp>) -> IoFuture<'_, CapturedSnapshot> {
        panic!("fresh capture during replay")
    }
    fn open_snapshot<'a>(&'a self, p: &'a SnapshotRef) -> IoFuture<'a, Arc<dyn BackendSnapshot>> {
        self.0.open_snapshot(p)
    }
    fn changes<'a>(
        &'a self,
        a: &'a SnapshotRef,
        t: &'a SnapshotRef,
        c: Option<&'a PageCursor>,
        s: PageSize,
    ) -> IoFuture<'a, Page<ChangeBatch>> {
        self.0.changes(a, t, c, s)
    }
    fn subscribe(&self) -> IoFuture<'_, Box<dyn ChangeHintSource>> {
        self.0.subscribe()
    }
}
async fn record(
    f: &ReferenceFixture,
    q: &PublishedArtifact,
) -> PreparedExecution<cdb_testkit::memory::MemoryContext> {
    prepare_recorded(
        draft(f, q),
        &f.backend,
        &f.backend,
        &f.principal,
        &Provider {
            f,
            replay: false,
            missing: false,
        },
        None,
        ExecutionOptions::default(),
    )
    .await
    .unwrap()
}
async fn replay(
    f: &ReferenceFixture,
    d: &ReplayData,
) -> Result<PreparedReplay<cdb_testkit::memory::MemoryContext>> {
    prepare_replay(
        d,
        &NoCapture(&f.backend),
        &f.backend,
        &f.principal,
        &Provider {
            f,
            replay: true,
            missing: false,
        },
        ExecutionOptions::default(),
    )
    .await
}
fn deny(f: &ReferenceFixture, target: &str) {
    let mut p = allow_policy()
        .unwrap()
        .projection()
        .as_object()
        .unwrap()
        .clone();
    let mut rules = p.get("policies").unwrap().as_array().unwrap().to_vec();
    let rule = format!(
        r#"{{"@id":"https://fixture.example/deny","@type":["https://ns.flur.ee/db#AccessPolicy","https://fixture.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":false,"https://ns.flur.ee/db#onSubject":"{target}"}}"#
    );
    rules.push(V::parse(rule.as_bytes(), Limits::default()).unwrap());
    p.insert("policies".into(), V::Array(rules));
    f.backend
        .set_policy(PolicySet::from_value(&V::Object(p)).unwrap())
        .unwrap();
}
#[tokio::test]
async fn real_walk_reproduces_without_capture_or_landing_resolution() {
    let (f, q) = setup(&query("A", true)).await;
    let recorded = record(&f, &q).await;
    assert_eq!(recorded.data().data().landings.len(), 1);
    assert!(recorded.data().data().reads.len() > 10);
    let durable = ReplayData::read(
        &recorded.data().bytes(Limits::default()).unwrap(),
        Limits::default(),
    )
    .unwrap();
    let replayed = replay(&f, &durable).await.unwrap();
    assert_eq!(replayed.verdict(), ReplayVerdict::Reproduced);
    let wire = V::parse(replayed.wire_bytes(), Limits::default()).unwrap();
    assert_eq!(
        wire.field("response").unwrap(),
        recorded.data().data().response.payload()
    );
}
#[tokio::test]
async fn explain_false_still_records_landings_and_empty_outcome() {
    for anchor in ["A", "missing"] {
        let (f, q) = setup(&query(anchor, false)).await;
        let r = record(&f, &q).await;
        assert_eq!(
            r.data().data().response.payload().field("explain").unwrap(),
            &V::Null
        );
        assert_eq!(r.data().data().landings.len(), usize::from(anchor == "A"));
        if anchor == "missing" {
            assert_eq!(
                r.data().data().reads[0].key.field("notices").unwrap(),
                &V::Array(vec![V::string("empty_landing")])
            );
        }
        assert_eq!(
            replay(&f, r.data()).await.unwrap().verdict(),
            ReplayVerdict::Reproduced
        );
    }
}
#[tokio::test]
async fn late_grant_is_frozen_and_revocation_denies_whole_replay() {
    let (f, q) = setup(&query("A", false)).await;
    deny(&f, "https://e/ac");
    let r = record(&f, &q).await;
    assert!(r.data().data().policy.iter().any(|p| !p.allowed));
    f.backend.set_policy(allow_policy().unwrap()).unwrap();
    assert_eq!(
        replay(&f, r.data()).await.unwrap().verdict(),
        ReplayVerdict::Reproduced
    );
    deny(&f, "https://e/ab");
    assert_eq!(
        replay(&f, r.data()).await.err().unwrap().kind,
        ErrorKind::Denied
    );
}
#[tokio::test]
async fn raw_hash_extra_missing_and_boundary_tamper_cannot_reproduce() {
    let (f, q) = setup(&query("A", false)).await;
    let r = record(&f, &q).await;
    for change in 0..4 {
        let mut d = r.data().data().clone();
        match change {
            0 => d.reads.last_mut().unwrap().result_hash = ContentHash::of_bytes(b"wrong"),
            1 => {
                d.reads.push(d.reads.last().unwrap().clone());
            }
            2 => {
                d.reads.pop();
            }
            _ => d.reads[0].result_hash = ContentHash::of_bytes(b"wrong"),
        }
        let d = ReplayData::new(d, Limits::default()).unwrap();
        assert_eq!(
            replay(&f, &d).await.unwrap().verdict(),
            ReplayVerdict::NotReplayable
        );
    }
}
#[tokio::test]
async fn negative_lifecycle_observation_is_verified() {
    let (f, q) = setup(&query("A", false)).await;
    let r = record(&f, &q).await;
    let mut d = r.data().data().clone();
    let read = d
        .reads
        .iter_mut()
        .find(|r| r.operation.as_str().ends_with("/lifecycle"))
        .unwrap();
    read.result_hash = ContentHash::of_bytes(b"changed empty enumeration");
    assert_eq!(
        replay(&f, &ReplayData::new(d, Limits::default()).unwrap())
            .await
            .unwrap()
            .verdict(),
        ReplayVerdict::NotReplayable
    );
}
#[tokio::test]
async fn stable_recording_identity_still_requires_matching_source_build_and_abi() {
    let (f, q) = setup(&query("A", false)).await;
    let r = record(&f, &q).await;
    // Product/crate naming is not a migration of the persisted engine identity.
    assert_eq!(r.data().data().engine.name.as_str(), "ctxql-engine");
    assert_eq!(
        replay(&f, r.data()).await.unwrap().verdict(),
        ReplayVerdict::Reproduced
    );
    for change in 0..3 {
        let mut d = r.data().data().clone();
        match change {
            0 => d.replay_abi = VersionId::new("future").unwrap(),
            // Renamed paths/source spellings change the raw build commitment.
            // Keeping the engine name does not authorize a different build.
            1 => d.engine.build = ContentHash::of_bytes(b"different source tree"),
            _ => d.engine.name = ResourceId::new("cdb-engine").unwrap(),
        }
        assert_eq!(
            replay(&f, &ReplayData::new(d, Limits::default()).unwrap())
                .await
                .unwrap()
                .verdict(),
            ReplayVerdict::NotReplayable
        );
    }
    let p = Provider {
        f: &f,
        replay: true,
        missing: true,
    };
    assert_eq!(
        prepare_replay(
            r.data(),
            &NoCapture(&f.backend),
            &f.backend,
            &f.principal,
            &p,
            ExecutionOptions::default()
        )
        .await
        .unwrap()
        .verdict(),
        ReplayVerdict::NotReplayable
    );
}
#[tokio::test]
async fn complete_policy_preflight_includes_unused_source_grant() {
    let (f, q) = setup(&query("A", false)).await;
    let r = record(&f, &q).await;
    let mut d = r.data().data().clone();
    d.policy.push(PolicyObservation {
        resource: ResourceId::new("https://e/C").unwrap(),
        predicate: None,
        allowed: true,
    });
    let d = ReplayData::new(d, Limits::default()).unwrap();
    deny(&f, "https://e/C");
    assert_eq!(replay(&f, &d).await.err().unwrap().kind, ErrorKind::Denied);
}
#[tokio::test]
async fn trace_and_work_limits_release_no_capability() {
    let (f, q) = setup(&query("A", false)).await;
    let options = ExecutionOptions {
        max_work: 1,
        ..ExecutionOptions::default()
    };
    assert_eq!(
        prepare_recorded(
            draft(&f, &q),
            &f.backend,
            &f.backend,
            &f.principal,
            &Provider {
                f: &f,
                replay: false,
                missing: false
            },
            None,
            options
        )
        .await
        .err()
        .unwrap()
        .kind,
        ErrorKind::Limit
    );
    let r = record(&f, &q).await;
    let options = ExecutionOptions {
        limits: Limits::new(1000, 64, 2, 1000, 1000).unwrap(),
        ..ExecutionOptions::default()
    };
    assert_eq!(
        prepare_replay(
            r.data(),
            &NoCapture(&f.backend),
            &f.backend,
            &f.principal,
            &Provider {
                f: &f,
                replay: true,
                missing: false
            },
            options
        )
        .await
        .err()
        .unwrap()
        .kind,
        ErrorKind::Limit
    );
}
#[tokio::test]
async fn changed_expected_response_diverges_but_returns_new_computation() {
    use cdb_core::canonical::{CanonicalProjection, Domain};
    let (f, q) = setup(&query("A", false)).await;
    let r = record(&f, &q).await;
    let mut d = r.data().data().clone();
    let mut payload = d.response.payload().as_object().unwrap().clone();
    payload.insert("graph_status".into(), V::string("ready"));
    d.response = CanonicalProjection::from_payload(Domain::Response, V::Object(payload)).unwrap();
    d.response_hash = d.response.hash(Limits::default()).unwrap();
    let changed = ReplayData::new(d, Limits::default()).unwrap();
    let replayed = replay(&f, &changed).await.unwrap();
    assert_eq!(replayed.verdict(), ReplayVerdict::Diverged);
    let wire = V::parse(replayed.wire_bytes(), Limits::default()).unwrap();
    assert_eq!(
        wire.field("response").unwrap(),
        r.data().data().response.payload()
    );
}
#[tokio::test]
async fn unsupported_stored_plan_does_not_recompile_defaults() {
    use cdb_core::canonical::{CanonicalProjection, Domain};
    let (f, q) = setup(&query("A", false)).await;
    let r = record(&f, &q).await;
    let mut d = r.data().data().clone();
    let mut payload = d.plan.payload().clone();
    let V::Object(p) = &mut payload else {
        unreachable!()
    };
    let V::Object(c) = p.get_mut("config").unwrap() else {
        unreachable!()
    };
    let V::Object(runtime) = c.get_mut("runtime").unwrap() else {
        unreachable!()
    };
    runtime.insert(
        "candidate_order".into(),
        V::Array(vec![V::string("unsupported")]),
    );
    d.plan = CanonicalProjection::from_payload(Domain::Plan, payload).unwrap();
    d.plan_hash = d.plan.hash(Limits::default()).unwrap();
    assert_eq!(
        replay(&f, &ReplayData::new(d, Limits::default()).unwrap())
            .await
            .unwrap()
            .verdict(),
        ReplayVerdict::NotReplayable
    );
}
#[tokio::test]
async fn target_injection_and_seed_limit_notice_survive_without_explain() {
    let text = r#"{"about":[{"from":["A","B"],"to":["B"],"match":"exact"}],"bounds":{"max_depth":1,"seed_limit":1},"return":{"explain":false}}"#;
    let (f, q) = setup(text).await;
    let r = record(&f, &q).await;
    assert_eq!(r.data().data().landings.len(), 2);
    assert_eq!(
        r.data().data().reads[0].key.field("notices").unwrap(),
        &V::Array(vec![V::string("seed_limit")])
    );
    assert_eq!(
        replay(&f, r.data()).await.unwrap().verdict(),
        ReplayVerdict::Reproduced
    );
    let mut d = r.data().data().clone();
    d.landings.reverse();
    let d = ReplayData::new(d, Limits::default()).unwrap();
    assert_eq!(
        replay(&f, &d).await.unwrap().verdict(),
        ReplayVerdict::NotReplayable
    );
}
#[tokio::test]
async fn original_catalog_is_retained_losslessly_and_replays() {
    let (f, q) = setup(&query("A", false)).await;
    let prepared = prepare_recorded(
        draft(&f, &q),
        &f.backend,
        &f.backend,
        &f.principal,
        &f,
        None,
        ExecutionOptions::default(),
    )
    .await
    .unwrap();
    let catalog = &prepared.data().data().catalog;
    assert!(catalog.iter().any(|entry| entry.label.is_none()));
    assert!(catalog.iter().any(|entry| entry.dependencies.is_empty()));
    assert!(catalog
        .iter()
        .enumerate()
        .any(|(i, entry)| catalog[..i].iter().any(|other| other.id == entry.id)));
    let retained = ReplayData::read(
        &prepared.data().bytes(Limits::default()).unwrap(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(&retained.data().catalog, catalog);
    assert_eq!(
        prepare_replay(
            &retained,
            &f.backend,
            &f.backend,
            &f.principal,
            &f,
            ExecutionOptions::default()
        )
        .await
        .unwrap()
        .verdict(),
        ReplayVerdict::Reproduced
    );
}
#[tokio::test]
async fn missing_or_denied_governance_scope_fails_closed() {
    let (f, q) = setup(&query("A", false)).await;
    deny(&f, REQUIRED_SCOPES[0]);
    assert_eq!(
        prepare_recorded(
            draft(&f, &q),
            &f.backend,
            &f.backend,
            &f.principal,
            &Provider {
                f: &f,
                replay: false,
                missing: false
            },
            None,
            ExecutionOptions::default()
        )
        .await
        .err()
        .unwrap()
        .kind,
        ErrorKind::Denied
    );
}

#[tokio::test]
async fn pre_cap_landing_outcomes_are_bound_to_roles_counts_and_notices() {
    let (f, q) = setup(&query("A", false)).await;
    let prepared = record(&f, &q).await;
    for change in 0..6 {
        let mut data = prepared.data().data().clone();
        let V::Object(marker) = &mut data.reads[0].key else {
            unreachable!()
        };
        let V::Array(outcomes) = marker.get_mut("outcomes").unwrap() else {
            unreachable!()
        };
        match change {
            0 => outcomes.clear(),
            1 => outcomes.push(outcomes[0].clone()),
            _ => {
                let V::Object(outcome) = &mut outcomes[0] else {
                    unreachable!()
                };
                match change {
                    2 => {
                        outcome.insert("matched".into(), V::integer(0));
                    }
                    3 => {
                        outcome.insert("matched".into(), V::integer(999));
                    }
                    4 => {
                        outcome.insert("role".into(), V::string("to"));
                    }
                    _ => {
                        outcome.insert("block_index".into(), V::integer(1));
                    }
                }
            }
        }
        data.reads[0].result_hash = ContentHash::of_bytes(
            &data.reads[0]
                .key
                .canonical_bytes(Limits::default())
                .unwrap(),
        );
        let data = ReplayData::new(data, Limits::default()).unwrap();
        assert_eq!(
            replay(&f, &data).await.unwrap().verdict(),
            ReplayVerdict::NotReplayable,
            "change {change}"
        );
    }
}
