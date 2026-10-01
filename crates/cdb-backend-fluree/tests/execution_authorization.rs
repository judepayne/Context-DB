use cdb_backend_fluree::{
    execution_authorization::{exact_invocation_role, ExactInvocationRequirement},
    policy::PolicyState,
    runs::{ExternalPublicationFence, Operation},
    AuthorityOptions, FlureeBackend,
};
use cdb_core::{
    admission::{AdmissionBatch, DependencyRecord, Fact, FactTerm, ResourceChange, ResourceKind},
    artifact::ArtifactRef,
    canonical::CanonicalProjection,
    contracts::{GraphBackend, PolicyService},
    id::*,
    recording::*,
    recording_v3::*,
    CanonicalValue as V, Error, ErrorKind, Limits, Result,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
#[path = "../../cdb-core/tests/common/mod.rs"]
mod common;
use common::fixture;
fn input(snapshot: cdb_core::snapshot::SnapshotRef) -> ReplayDataInput {
    let l = Limits::default();
    let mut p = fixture("plan");
    let V::Object(root) = &mut p else {
        unreachable!()
    };
    let V::Object(payload) = root.get_mut("payload").unwrap() else {
        unreachable!()
    };
    let V::Object(a) = payload.get_mut("artifacts").unwrap() else {
        unreachable!()
    };
    a.insert("query".into(), a["config"].clone());
    let plan = CanonicalProjection::read(&p.canonical_bytes(l).unwrap(), l).unwrap();
    let config = ArtifactRef::from_value(
        plan.payload()
            .field("artifacts")
            .unwrap()
            .field("config")
            .unwrap(),
    )
    .unwrap();
    ReplayDataInput {
        snapshot: snapshot.clone(),
        requested_snapshot: snapshot.clone(),
        as_of: cdb_core::Timestamp::parse("1969-12-31T23:59:59.999Z").unwrap(),
        stale: false,
        // Independent Python hashlib over the existing vector with query=config binding.
        plan_hash: ContentHash::parse(
            "sha256:c62caf74fbecd39100be7fa9fbcbcea7f9c0bb84815814c125fcfc61bc9fe5a3",
        )
        .unwrap(),
        plan,
        response: CanonicalProjection::read(&fixture("response").canonical_bytes(l).unwrap(), l)
            .unwrap(),
        response_hash: ContentHash::parse(
            "sha256:17489b4f791a43e0a36b1af79ea9eacd60e7ecbfda760516503be24ca0dba55a",
        )
        .unwrap(),
        query: config.clone(),
        config,
        profile: None,
        engine: RecordingEngine {
            name: ResourceId::new("engine").unwrap(),
            version: VersionId::new("1").unwrap(),
            build: ContentHash::of_bytes(b"engine"),
        },
        replay_abi: VersionId::new("native/v1").unwrap(),
        landings: vec![],
        catalog: vec![],
        policy: vec![],
        reads: vec![],
        scopes: REQUIRED_SCOPES
            .iter()
            .map(|s| ResourceId::new(*s).unwrap())
            .collect(),
        functions: vec![],
    }
}

fn options(path: &std::path::Path) -> AuthorityOptions {
    AuthorityOptions::new(
        path.join("db"),
        "runs:main".into(),
        BackendId::new("fluree").unwrap(),
        AuthorityId::new("owner").unwrap(),
        GraphId::new("graph").unwrap(),
    )
}
async fn setup() -> (tempfile::TempDir, Arc<FlureeBackend>) {
    let dir = tempfile::tempdir().unwrap();
    let b = Arc::new(FlureeBackend::create(options(dir.path())).await.unwrap());
    b.bootstrap_governance().await.unwrap();
    let mut state = PolicyState::deny_all().unwrap();
    let roles = [Operation::Query, Operation::Read]
        .into_iter()
        .map(|o| Iri::http(o.role()).unwrap())
        .collect();
    state
        .principals
        .insert(PrincipalId::new("alice").unwrap(), (true, roles));
    state.principals.insert(
        PrincipalId::new("bob").unwrap(),
        (
            true,
            [Operation::Read]
                .into_iter()
                .map(|o| Iri::http(o.role()).unwrap())
                .collect(),
        ),
    );
    state.policy = cdb_core::policy::PolicySet::parse(br#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{"@id":"https://test.example/allow","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true}]}"#, Limits::default()).unwrap();
    b.set_policy_state(&IdempotencyKey::new("policy").unwrap(), &state)
        .await
        .unwrap();
    (dir, b)
}
async fn envelope(b: &FlureeBackend) -> RunEnvelope {
    RunEnvelope::new(
        RunId::new("r1").unwrap(),
        PrincipalId::new("alice").unwrap(),
        ContentHash::of_bytes(b"operation"),
        ReplayData::new(input(b.head().await.unwrap()), Limits::default()).unwrap(),
        Limits::default(),
    )
    .unwrap()
}
async fn envelope_v3(b: &FlureeBackend, id: &str) -> RunEnvelopeV3 {
    envelope_v3_with_policy(b, id, vec![]).await
}

async fn envelope_v3_with_policy(
    b: &FlureeBackend,
    id: &str,
    policy: Vec<PolicyObservation>,
) -> RunEnvelopeV3 {
    let mut base = input(b.head().await.unwrap());
    base.replay_abi = VersionId::new(REPLAY_ABI).unwrap();
    base.policy = policy.clone();
    let identity = V::object([
        ("phase".into(), V::string("preparation")),
        ("evaluation".into(), V::integer(0)),
        ("predicate".into(), V::integer(0)),
        ("attempt".into(), V::integer(0)),
        ("ordinal".into(), V::integer(0)),
    ])
    .unwrap();
    let lane = V::object([
        ("identity".into(), identity.clone()),
        ("closed".into(), V::Bool(true)),
        ("outcome".into(), V::string("empty")),
        ("reads".into(), V::Array(vec![])),
        (
            "policy".into(),
            V::Array(
                policy
                    .iter()
                    .map(|observation| {
                        V::object([
                            ("resource".into(), V::string(observation.resource.as_str())),
                            (
                                "predicate".into(),
                                observation
                                    .predicate
                                    .as_ref()
                                    .map(|predicate| V::string(predicate.as_str()))
                                    .unwrap_or(V::Null),
                            ),
                            ("allowed".into(), V::Bool(observation.allowed)),
                        ])
                        .unwrap()
                    })
                    .collect(),
            ),
        ),
        (
            "scopes".into(),
            V::Array(base.scopes.iter().map(|s| V::string(s.as_str())).collect()),
        ),
        ("function_counts".into(), V::Array(vec![])),
    ])
    .unwrap();
    let executor = base.engine.clone();
    let replay = ReplayDataV3::new(
        ReplayDataV3Input {
            base,
            lanes: vec![lane],
            expected_lanes: vec![identity],
            functions: vec![],
            prepared: vec![],
            release_evidence: vec![],
            executor,
        },
        Limits::default(),
    )
    .unwrap();
    RunEnvelopeV3::new(
        RunId::new(id).unwrap(),
        PrincipalId::new("alice").unwrap(),
        ContentHash::of_bytes(b"v3-operation"),
        replay,
        Limits::default(),
    )
    .unwrap()
}
fn function_v3_input(
    snapshot: cdb_core::snapshot::SnapshotRef,
) -> (ReplayDataV3Input, ArtifactRef, ResourceId) {
    let l = Limits::default();
    let mut base = input(snapshot);
    base.replay_abi = VersionId::new(REPLAY_ABI).unwrap();
    let source = " { \"kind\" : \"test\" } ";
    let manifest = ArtifactRef::new(
        Iri::new("urn:function:manifest").unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(source.as_bytes()),
    );
    let destination = ResourceId::new("urn:destination:original").unwrap();
    let mut plan = base.plan.envelope();
    let V::Object(root) = &mut plan else {
        unreachable!()
    };
    let V::Object(payload) = root.get_mut("payload").unwrap() else {
        unreachable!()
    };
    let V::Object(config) = payload.get_mut("config").unwrap() else {
        unreachable!()
    };
    config.insert(
        "external_functions".into(),
        V::object([(
            "fn:test".into(),
            V::object([
                ("version".into(), V::string("1")),
                ("manifest_uri".into(), V::string(manifest.iri().as_str())),
                ("manifest_hash".into(), V::string(manifest.hash().as_str())),
                ("deterministic".into(), V::Bool(true)),
            ])
            .unwrap(),
        )])
        .unwrap(),
    );
    base.plan = CanonicalProjection::read(&plan.canonical_bytes(l).unwrap(), l).unwrap();
    base.plan_hash = base.plan.hash(l).unwrap();
    let identity = V::object([
        ("phase".into(), V::string("preparation")),
        ("evaluation".into(), V::integer(0)),
        ("predicate".into(), V::integer(0)),
        ("attempt".into(), V::integer(0)),
        ("ordinal".into(), V::integer(0)),
    ])
    .unwrap();
    let lane = V::object([
        ("identity".into(), identity.clone()),
        ("closed".into(), V::Bool(true)),
        ("outcome".into(), V::string("accepted")),
        ("reads".into(), V::Array(vec![])),
        ("policy".into(), V::Array(vec![])),
        (
            "scopes".into(),
            V::Array(base.scopes.iter().map(|s| V::string(s.as_str())).collect()),
        ),
        (
            "function_counts".into(),
            V::Array(vec![V::object([
                ("count".into(), V::integer(1)),
                ("name".into(), V::string("fn:test")),
            ])
            .unwrap()]),
        ),
    ])
    .unwrap();
    let function = V::object([
        ("name".into(), V::string("fn:test")),
        ("manifest".into(), manifest.projection()),
        ("source".into(), V::string(source)),
        ("deterministic".into(), V::Bool(true)),
        ("replay".into(), V::string("exact")),
        ("count".into(), V::integer(1)),
        (
            "input_root".into(),
            V::string(ContentHash::of_bytes(b"input").as_str()),
        ),
        (
            "output_root".into(),
            V::string(ContentHash::of_bytes(b"output").as_str()),
        ),
        (
            "destinations".into(),
            V::Array(vec![V::string(destination.as_str())]),
        ),
    ])
    .unwrap();
    let executor = base.engine.clone();
    (
        ReplayDataV3Input {
            base,
            lanes: vec![lane],
            expected_lanes: vec![identity],
            functions: vec![function],
            prepared: vec![],
            release_evidence: vec![],
            executor,
        },
        manifest,
        destination,
    )
}

impl cdb_backend_fluree::execution_authorization::ExecutionFence for Fence {
    fn check_disclosure(&self) -> Result<()> {
        self.check()
    }
}
async fn execution(
    b: &FlureeBackend,
    run: &RunEnvelope,
) -> cdb_backend_fluree::execution_authorization::ExecutionAuthorization {
    b.capture_execution(
        b.issue_principal(run.owner().clone()).await.unwrap(),
        run.replay().data().snapshot.clone(),
        run.replay().data().as_of,
        run.id().clone(),
        run.replay().data().plan_hash.clone(),
        Operation::Query,
    )
    .await
    .unwrap()
}
async fn execution_v3(
    b: &FlureeBackend,
    run: &RunEnvelopeV3,
) -> cdb_backend_fluree::execution_authorization::ExecutionAuthorization {
    let execution = b
        .capture_execution(
            b.issue_principal(run.owner().clone()).await.unwrap(),
            run.replay().data().snapshot.clone(),
            run.replay().data().as_of,
            run.id().clone(),
            run.replay().data().plan_hash.clone(),
            Operation::Query,
        )
        .await
        .unwrap();
    for scope in &run.replay().data().scopes {
        assert!(b.original_resource_allowed(&execution, scope).unwrap());
    }
    for observation in &run.replay().data().policy {
        if observation.allowed {
            assert!(match &observation.predicate {
                Some(predicate) => b
                    .original_fact_allowed(&execution, &observation.resource, predicate)
                    .unwrap(),
                None => b
                    .original_resource_allowed(&execution, &observation.resource)
                    .unwrap(),
            });
        }
    }
    execution
}
#[tokio::test]
async fn unrelated_commit_refreshes_without_re_evaluation_and_retry_uses_original() {
    let (_dir, b) = setup().await;
    let run = envelope(&b).await;
    let e = execution(&b, &run).await;
    assert!(b
        .original_resource_allowed(&e, &ResourceId::new(REQUIRED_SCOPES[0]).unwrap())
        .unwrap());
    let state = b.policy_state().await.unwrap();
    b.set_policy_state(&IdempotencyKey::new("unrelated").unwrap(), &state)
        .await
        .unwrap();
    let original = e.data_snapshot().clone();
    let receipt = b
        .clone()
        .guarded_execution_commit(
            e.clone(),
            e.release_footprint().unwrap(),
            run.clone(),
            Box::new(Fence(Arc::new(AtomicBool::new(false)))),
            |_, _| Ok(()),
        )
        .await
        .unwrap();
    assert_ne!(receipt, original);
    assert_eq!(e.data_snapshot(), &original);
    let retry = b
        .clone()
        .guarded_execution_commit(
            e.clone(),
            e.release_footprint().unwrap(),
            run.clone(),
            Box::new(Fence(Arc::new(AtomicBool::new(false)))),
            move |stored, _| {
                assert_eq!(stored, &run);
                Ok(())
            },
        )
        .await
        .unwrap();
    assert_eq!(retry, receipt);
}
#[tokio::test]
async fn role_revocation_is_denied_but_original_positive_remains() {
    let (_dir, b) = setup().await;
    let run = envelope(&b).await;
    let e = execution(&b, &run).await;
    let resource = ResourceId::new(REQUIRED_SCOPES[0]).unwrap();
    assert!(b.original_resource_allowed(&e, &resource).unwrap());
    let mut state = b.policy_state().await.unwrap();
    state.principals.get_mut(run.owner()).unwrap().1.clear();
    b.set_policy_state(&IdempotencyKey::new("revoke-role").unwrap(), &state)
        .await
        .unwrap();
    assert!(b.original_resource_allowed(&e, &resource).unwrap());
    let error = b
        .clone()
        .guarded_execution_release(
            e.clone(),
            e.release_footprint().unwrap(),
            Box::new(Fence(Arc::new(AtomicBool::new(false)))),
            || Ok(vec![]),
            |_| panic!("revoked release"),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Denied);
}
#[tokio::test]
async fn foreign_footprint_and_post_callback_cancellation_fail_closed() {
    let (_dir, b) = setup().await;
    let run = envelope(&b).await;
    let e = execution(&b, &run).await;
    let other = execution(&b, &run).await;
    let error = b
        .clone()
        .guarded_execution_release(
            e.clone(),
            other.release_footprint().unwrap(),
            Box::new(Fence(Arc::new(AtomicBool::new(false)))),
            || Ok(vec![]),
            |_| panic!("foreign footprint"),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Denied);
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = cancelled.clone();
    let error = b
        .clone()
        .guarded_execution_release(
            e.clone(),
            e.release_footprint().unwrap(),
            Box::new(Fence(cancelled)),
            move || {
                flag.store(true, Ordering::SeqCst);
                Ok(vec![1])
            },
            |_| panic!("cancelled release"),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Denied);
}
#[tokio::test]
async fn lazy_false_does_not_broaden_after_grant() {
    let (_dir, b) = setup().await;
    let mut state = b.policy_state().await.unwrap();
    state
        .principals
        .get_mut(&PrincipalId::new("alice").unwrap())
        .unwrap()
        .1
        .remove(&Iri::http(Operation::Read.role()).unwrap());
    b.set_policy_state(&IdempotencyKey::new("remove-read").unwrap(), &state)
        .await
        .unwrap();
    let run = envelope(&b).await;
    let e = execution(&b, &run).await;
    assert!(!b
        .original_resource_allowed(&e, &ResourceId::new(REQUIRED_SCOPES[0]).unwrap())
        .unwrap());
    state
        .principals
        .get_mut(run.owner())
        .unwrap()
        .1
        .insert(Iri::http(Operation::Read.role()).unwrap());
    b.set_policy_state(&IdempotencyKey::new("grant-read").unwrap(), &state)
        .await
        .unwrap();
    assert!(!b
        .original_resource_allowed(&e, &ResourceId::new(REQUIRED_SCOPES[0]).unwrap())
        .unwrap());
    assert!(!b
        .original_resource_allowed(&e, &ResourceId::new(REQUIRED_SCOPES[1]).unwrap())
        .unwrap());
}
#[tokio::test]
async fn barrier_peer_commit_does_not_restart_original_execution() {
    let (_dir, b) = setup().await;
    let run = envelope(&b).await;
    let e = execution(&b, &run).await;
    let original = e.data_snapshot().clone();
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let proceed = Arc::new(tokio::sync::Notify::new());
    let worker = b.clone();
    let entered = barrier.clone();
    let resume = proceed.clone();
    let paused = tokio::spawn(async move {
        assert!(worker
            .original_resource_allowed(&e, &ResourceId::new(REQUIRED_SCOPES[0]).unwrap())
            .unwrap());
        entered.wait().await;
        resume.notified().await;
        worker
            .guarded_execution_commit(
                e.clone(),
                e.release_footprint().unwrap(),
                run,
                Box::new(Fence(Arc::new(AtomicBool::new(false)))),
                move |stored, _| {
                    assert_eq!(&stored.replay().data().snapshot, &original);
                    Ok(())
                },
            )
            .await
    });
    barrier.wait().await;
    let peer = RunEnvelope::new(
        RunId::new("peer").unwrap(),
        PrincipalId::new("alice").unwrap(),
        ContentHash::of_bytes(b"peer"),
        ReplayData::new(input(b.head().await.unwrap()), Limits::default()).unwrap(),
        Limits::default(),
    )
    .unwrap();
    let peer_e = execution(&b, &peer).await;
    b.clone()
        .guarded_execution_commit(
            peer_e.clone(),
            peer_e.release_footprint().unwrap(),
            peer,
            Box::new(Fence(Arc::new(AtomicBool::new(false)))),
            |_, _| Ok(()),
        )
        .await
        .unwrap();
    proceed.notify_one();
    paused.await.unwrap().unwrap();
}
#[tokio::test]
async fn checked_actions_return_actual_heads_and_preserve_earlier_subsets() {
    let (_dir, b) = setup().await;
    let run = envelope(&b).await;
    let e = execution(&b, &run).await;
    let first_resource = ResourceId::new(REQUIRED_SCOPES[0]).unwrap();
    assert!(b.original_resource_allowed(&e, &first_resource).unwrap());
    let expected_first_head = b.head().await.unwrap();
    let (_, first) = b
        .clone()
        .guarded_execution_action_checked(
            e.clone(),
            e.release_footprint().unwrap(),
            Box::new(Fence(Arc::new(AtomicBool::new(false)))),
            || Ok(()),
        )
        .await
        .unwrap();
    assert_eq!(first.authorization_head(), &expected_first_head);
    assert_eq!(
        first
            .requirements_projection()
            .field("facts")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(first.requirements_hash(), first.requirements().hash());

    let state = b.policy_state().await.unwrap();
    b.set_policy_state(
        &IdempotencyKey::new("checked-head-advance").unwrap(),
        &state,
    )
    .await
    .unwrap();
    let second_resource = ResourceId::new(REQUIRED_SCOPES[1]).unwrap();
    assert!(b.original_resource_allowed(&e, &second_resource).unwrap());
    let expected_second_head = b.head().await.unwrap();
    let (_, second) = b
        .clone()
        .guarded_execution_action_checked(
            e.clone(),
            e.release_footprint().unwrap(),
            Box::new(Fence(Arc::new(AtomicBool::new(false)))),
            || Ok(()),
        )
        .await
        .unwrap();
    assert_eq!(second.authorization_head(), &expected_second_head);
    assert_ne!(first.authorization_head(), second.authorization_head());
    assert_eq!(
        second
            .requirements_projection()
            .field("facts")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        first
            .requirements_projection()
            .field("facts")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1,
        "later lazy observations must not rewrite the earlier receipt"
    );
    let evidence = first
        .release_evidence(ResourceId::new("release:first").unwrap(), Limits::default())
        .unwrap();
    assert_eq!(
        evidence.projection().field("authorization_head").unwrap(),
        &cdb_core::record_codec::snapshot_value(&expected_first_head)
    );
}

#[tokio::test]
async fn omitted_later_positive_dependency_is_denied() {
    let (_dir, b) = setup().await;
    let run = envelope(&b).await;
    let e = execution(&b, &run).await;
    let footprint = e.release_footprint().unwrap();
    assert!(b
        .original_resource_allowed(&e, &ResourceId::new(REQUIRED_SCOPES[0]).unwrap())
        .unwrap());
    let error = b
        .clone()
        .guarded_execution_release(
            e,
            footprint,
            Box::new(Fence(Arc::new(AtomicBool::new(false)))),
            || Ok(vec![]),
            |_| panic!("omitted dependency"),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Denied);
}
#[tokio::test]
async fn unrelated_data_commit_and_class_fact_scope_changes_are_revalidated() {
    let (_dir, b) = setup().await;
    let mut state = b.policy_state().await.unwrap();
    let class = Iri::http("https://test.example/Visible").unwrap();
    let property = Iri::http("https://test.example/value").unwrap();
    let resource = ResourceId::new("https://test.example/item").unwrap();
    let record = DependencyRecord::new(
        "ctxql-resource/v1",
        resource.clone(),
        ResourceKind::Identity,
        vec![Fact::new(
            property.clone(),
            FactTerm::Reference(ResourceId::new("https://test.example/value-object").unwrap()),
        )],
    )
    .unwrap();
    let batch = AdmissionBatch::new(
        vec![],
        vec![],
        vec![ResourceChange::Add(record)],
        vec![],
        V::object([]).unwrap(),
        Limits::default(),
    )
    .unwrap();
    GraphBackend::admit(b.as_ref(), &IdempotencyKey::new("data").unwrap(), &batch)
        .await
        .unwrap();
    state
        .classes
        .insert(resource.clone(), [class.clone()].into());
    for scope in REQUIRED_SCOPES {
        state
            .classes
            .insert(ResourceId::new(scope).unwrap(), [class.clone()].into());
    }
    state.policy = cdb_core::policy::PolicySet::parse(
        br#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{"@id":"https://test.example/class-view","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#onClass":"https://test.example/Visible","https://ns.flur.ee/db#allow":true}]}"#,
        Limits::default(),
    )
    .unwrap();
    b.set_policy_state(&IdempotencyKey::new("class-policy").unwrap(), &state)
        .await
        .unwrap();
    let run = envelope(&b).await;
    let e = execution(&b, &run).await;
    assert!(b.original_fact_allowed(&e, &resource, &property).unwrap());
    let scope = ResourceId::new(REQUIRED_SCOPES[0]).unwrap();
    assert!(b.original_resource_allowed(&e, &scope).unwrap());

    let unrelated = DependencyRecord::new(
        "ctxql-resource/v1",
        ResourceId::new("https://test.example/unrelated").unwrap(),
        ResourceKind::Identity,
        vec![Fact::new(
            Iri::http("https://test.example/name").unwrap(),
            FactTerm::Reference(ResourceId::new("https://test.example/other").unwrap()),
        )],
    )
    .unwrap();
    let unrelated = AdmissionBatch::new(
        vec![],
        vec![],
        vec![ResourceChange::Add(unrelated)],
        vec![],
        V::object([]).unwrap(),
        Limits::default(),
    )
    .unwrap();
    GraphBackend::admit(
        b.as_ref(),
        &IdempotencyKey::new("unrelated-data").unwrap(),
        &unrelated,
    )
    .await
    .unwrap();
    b.clone()
        .guarded_execution_release(
            e.clone(),
            e.release_footprint().unwrap(),
            Box::new(Fence(Arc::new(AtomicBool::new(false)))),
            || Ok(vec![]),
            |_| Ok(()),
        )
        .await
        .unwrap();

    // Policy bytes stay unchanged; removing current class data revokes both the
    // exact fact and completeness-scope requirements.
    state.classes.remove(&resource);
    state.classes.remove(&scope);
    b.set_policy_state(&IdempotencyKey::new("class-data-change").unwrap(), &state)
        .await
        .unwrap();
    assert_eq!(
        b.clone()
            .guarded_execution_release(
                e.clone(),
                e.release_footprint().unwrap(),
                Box::new(Fence(Arc::new(AtomicBool::new(false)))),
                || Ok(vec![]),
                |_| panic!("class/fact/scope revoked"),
            )
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Denied
    );
    assert!(b.original_fact_allowed(&e, &resource, &property).unwrap());
    assert!(b.original_resource_allowed(&e, &scope).unwrap());
}

#[tokio::test]
async fn exact_invocation_is_separate_from_read_and_bound_to_manifest_provider() {
    let (_dir, b) = setup().await;
    let run = envelope(&b).await;
    let manifest = ArtifactRef::new(
        Iri::http("https://test.example/function").unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(b"manifest"),
    );
    let provider = ResourceId::new("https://test.example/provider").unwrap();
    let requirement = ExactInvocationRequirement::new(manifest.clone(), provider.clone());
    let e = execution(&b, &run).await;
    assert!(
        !b.original_exact_invocation_allowed(&e, &requirement)
            .unwrap(),
        "readable policy alone must not disclose"
    );

    let mut state = b.policy_state().await.unwrap();
    state
        .principals
        .get_mut(run.owner())
        .unwrap()
        .1
        .insert(exact_invocation_role(&requirement).unwrap());
    b.set_policy_state(&IdempotencyKey::new("invocation-grant").unwrap(), &state)
        .await
        .unwrap();
    let granted = execution(&b, &run).await;
    assert!(b
        .original_exact_invocation_allowed(&granted, &requirement)
        .unwrap());
    let wrong_provider = ExactInvocationRequirement::new(
        manifest.clone(),
        ResourceId::new("https://test.example/wrong-provider").unwrap(),
    );
    let wrong_manifest = ExactInvocationRequirement::new(
        ArtifactRef::new(
            manifest.iri().clone(),
            VersionId::new("2").unwrap(),
            manifest.hash().clone(),
        ),
        provider,
    );
    assert!(!b
        .original_exact_invocation_allowed(&granted, &wrong_provider)
        .unwrap());
    assert!(!b
        .original_exact_invocation_allowed(&granted, &wrong_manifest)
        .unwrap());

    state
        .principals
        .get_mut(run.owner())
        .unwrap()
        .1
        .remove(&exact_invocation_role(&requirement).unwrap());
    b.set_policy_state(&IdempotencyKey::new("invocation-revoke").unwrap(), &state)
        .await
        .unwrap();
    assert_eq!(
        b.clone()
            .guarded_execution_release(
                granted.clone(),
                granted.release_footprint().unwrap(),
                Box::new(Fence(Arc::new(AtomicBool::new(false)))),
                || Ok(vec![]),
                |_| panic!("revoked invocation"),
            )
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Denied
    );
}

// The barrier intentionally blocks one worker inside the guarded callback;
// another worker must remain available to expire and release the waiter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_expiry_and_post_callback_fence_checks_prevent_release() {
    let (_dir, b) = setup().await;
    let run = envelope(&b).await;
    let holder = execution(&b, &run).await;
    let waiting = execution(&b, &run).await;
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let pair = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let held_pair = pair.clone();
    let owner = b.clone();
    let held = tokio::spawn(async move {
        owner
            .guarded_execution_release(
                holder.clone(),
                holder.release_footprint().unwrap(),
                Box::new(Fence(Arc::new(AtomicBool::new(false)))),
                move || {
                    entered_tx.send(()).unwrap();
                    let (lock, cv) = &*held_pair;
                    let mut released = lock.lock().unwrap();
                    while !*released {
                        let (guard, timeout) = cv
                            .wait_timeout(released, std::time::Duration::from_secs(10))
                            .unwrap();
                        assert!(
                            !timeout.timed_out(),
                            "guarded-release test barrier timed out"
                        );
                        released = guard;
                    }
                    Ok(vec![])
                },
                |_| Ok(()),
            )
            .await
    });
    tokio::task::spawn_blocking(move || {
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap()
    })
    .await
    .unwrap();
    let expired = Arc::new(AtomicBool::new(false));
    let waiter_owner = b.clone();
    let waiter_flag = expired.clone();
    let waiter = tokio::spawn(async move {
        waiter_owner
            .guarded_execution_release(
                waiting.clone(),
                waiting.release_footprint().unwrap(),
                Box::new(Fence(waiter_flag)),
                || Ok(vec![]),
                |_| panic!("expired queued release"),
            )
            .await
    });
    tokio::task::yield_now().await;
    expired.store(true, Ordering::SeqCst);
    let (lock, cv) = &*pair;
    *lock.lock().unwrap() = true;
    cv.notify_one();
    held.await.unwrap().unwrap();
    assert_eq!(waiter.await.unwrap().unwrap_err().kind, ErrorKind::Denied);
}

#[test]
fn v3_commit_requires_exact_stored_derived_footprint() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (_dir, b) = setup().await;
                    let run = envelope_v3(&b, "v3-exact-footprint").await;
                    let missing = b
                        .capture_execution(
                            b.issue_principal(run.owner().clone()).await.unwrap(),
                            run.replay().data().snapshot.clone(),
                            run.replay().data().as_of,
                            run.id().clone(),
                            run.replay().data().plan_hash.clone(),
                            Operation::Query,
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        b.clone()
                            .guarded_execution_commit_v3(
                                missing.clone(),
                                missing.release_footprint().unwrap(),
                                run.clone(),
                                Box::new(Fence(Arc::new(AtomicBool::new(false)))),
                                |_, _| Ok(()),
                            )
                            .await
                            .unwrap_err()
                            .kind,
                        ErrorKind::Denied
                    );

                    let extra = execution_v3(&b, &run).await;
                    assert!(b
                        .original_fact_allowed(
                            &extra,
                            &ResourceId::new(REQUIRED_SCOPES[0]).unwrap(),
                            &Iri::http("https://example.test/not-in-recording").unwrap(),
                        )
                        .unwrap());
                    assert_eq!(
                        b.clone()
                            .guarded_execution_commit_v3(
                                extra.clone(),
                                extra.release_footprint().unwrap(),
                                run,
                                Box::new(Fence(Arc::new(AtomicBool::new(false)))),
                                |_, _| Ok(()),
                            )
                            .await
                            .unwrap_err()
                            .kind,
                        ErrorKind::Denied
                    );
                })
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn v3_original_destination_substitution_is_rejected() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(v3_original_destination_substitution_check())
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn v3_original_destination_substitution_check() {
    let (_dir, b) = setup().await;
    let (mut replay_input, manifest, destination) = function_v3_input(b.head().await.unwrap());
    let requirement = ExactInvocationRequirement::new(manifest.clone(), destination.clone());
    let mut state = b.policy_state().await.unwrap();
    let roles = &mut state
        .principals
        .get_mut(&PrincipalId::new("alice").unwrap())
        .unwrap()
        .1;
    roles.insert(exact_invocation_role(&requirement).unwrap());
    roles.insert(Iri::http(Operation::Replay.role()).unwrap());
    b.set_policy_state(&IdempotencyKey::new("destination-grants").unwrap(), &state)
        .await
        .unwrap();

    let run_id = RunId::new("v3-destination").unwrap();
    let principal = b
        .issue_principal(PrincipalId::new("alice").unwrap())
        .await
        .unwrap();
    let execution = b
        .capture_execution(
            principal,
            replay_input.base.snapshot.clone(),
            replay_input.base.as_of,
            run_id.clone(),
            replay_input.base.plan_hash.clone(),
            Operation::Query,
        )
        .await
        .unwrap();
    assert!(b
        .original_exact_invocation_allowed(&execution, &requirement)
        .unwrap());
    for scope in &replay_input.base.scopes {
        assert!(b.original_resource_allowed(&execution, scope).unwrap());
    }
    let operation_hash = ContentHash::of_bytes(b"destination-operation");
    let owner = PrincipalId::new("alice").unwrap();
    b.clone()
        .guarded_execution_commit_v3_built(
            execution.clone(),
            execution.release_footprint().unwrap(),
            Box::new(Fence(Arc::new(AtomicBool::new(false)))),
            move |receipt| {
                let limits = Limits::default();
                let identity = LaneIdentityV3::from_value(&replay_input.expected_lanes[0])?;
                let callback = function_callback_id(&identity, 0, limits)?;
                for kind in ["enqueue", "consume"] {
                    replay_input.release_evidence.push(
                        receipt
                            .release_evidence(function_action_id(&callback, 1, kind)?, limits)?
                            .projection(),
                    );
                }
                replay_input.release_evidence.push(
                    receipt
                        .release_evidence(
                            ResourceId::new("precommit:destination").unwrap(),
                            limits,
                        )?
                        .projection(),
                );
                let replay = ReplayDataV3::new(replay_input, Limits::default())?;
                RunEnvelopeV3::new(run_id, owner, operation_hash, replay, Limits::default())
            },
            |_, _| Ok(()),
        )
        .await
        .unwrap();

    let principal = b
        .issue_principal(PrincipalId::new("alice").unwrap())
        .await
        .unwrap();
    let current = b.current(&principal).await.unwrap();
    let stored_id = RunId::new("v3-destination").unwrap();
    b.reopen_v3(&principal, &current, &stored_id).await.unwrap();
    let replay_authorization = b
        .prepare_recorded_replay(principal.clone(), &current, &stored_id)
        .await
        .unwrap();
    let replay_projection = replay_authorization.run().replay().projection();
    let lane = &replay_projection
        .field("lanes")
        .unwrap()
        .as_array()
        .unwrap()[0];
    let identity = LaneIdentityV3::from_value(lane.field("identity").unwrap()).unwrap();
    let callback = function_callback_id(&identity, 0, Limits::default()).unwrap();
    replay_authorization
        .action_footprint(b.as_ref(), &callback, vec![], requirement.clone())
        .unwrap();
    assert_eq!(
        replay_authorization
            .action_footprint(
                b.as_ref(),
                &callback,
                vec![(
                    ResourceId::new("https://test.example/unrecorded-currently-readable").unwrap(),
                    Iri::http("https://ns.flur.ee/db#view").unwrap(),
                )],
                requirement.clone(),
            )
            .err()
            .unwrap()
            .kind,
        ErrorKind::Denied
    );
    let substituted = ExactInvocationRequirement::new(
        manifest,
        ResourceId::new("urn:destination:substituted").unwrap(),
    );
    let mut state = b.policy_state().await.unwrap();
    let roles = &mut state
        .principals
        .get_mut(&PrincipalId::new("alice").unwrap())
        .unwrap()
        .1;
    roles.remove(&exact_invocation_role(&requirement).unwrap());
    roles.insert(exact_invocation_role(&substituted).unwrap());
    b.set_policy_state(
        &IdempotencyKey::new("destination-substitution").unwrap(),
        &state,
    )
    .await
    .unwrap();
    let current = b.current(&principal).await.unwrap();
    assert_eq!(
        b.reopen_v3(&principal, &current, &RunId::new("v3-destination").unwrap(),)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Denied
    );
    assert_eq!(
        b.retry_original_v3(
            &principal,
            &current,
            &RunId::new("v3-destination").unwrap(),
            &ContentHash::of_bytes(b"destination-operation"),
        )
        .await
        .unwrap_err()
        .kind,
        ErrorKind::Denied
    );
}

#[test]
fn v3_commit_reopen_retry_preserve_bytes_pin_receipt_and_payload_protection() {
    // Reserve the native SDK debug stack explicitly, as in the existing probes.
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(v3_commit_reopen_retry_check())
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn v3_commit_reopen_retry_check() {
    let (_dir, b) = setup().await;
    let optional = ResourceId::new("https://test.example/later-visible").unwrap();
    let hidden = Iri::http("https://test.example/Hidden").unwrap();
    let mut initial_policy = b.policy_state().await.unwrap();
    initial_policy
        .classes
        .insert(optional.clone(), [hidden].into());
    initial_policy.policy = cdb_core::policy::PolicySet::parse(
        br#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{"@id":"https://test.example/allow","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true},{"@id":"https://test.example/deny-hidden","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#onClass":"https://test.example/Hidden","https://ns.flur.ee/db#allow":false}]}"#,
        Limits::default(),
    )
    .unwrap();
    b.set_policy_state(
        &IdempotencyKey::new("v3-frozen-false-policy").unwrap(),
        &initial_policy,
    )
    .await
    .unwrap();
    let run = envelope_v3_with_policy(
        &b,
        "v3-run",
        vec![PolicyObservation {
            resource: optional.clone(),
            predicate: None,
            allowed: false,
        }],
    )
    .await;
    let original_bytes = run.bytes(Limits::default()).unwrap();
    let original_pin = run.replay().data().snapshot.clone();
    let sink_bytes = original_bytes.clone();
    let e = execution_v3(&b, &run).await;
    let receipt = b
        .clone()
        .guarded_execution_commit_v3(
            e.clone(),
            e.release_footprint().unwrap(),
            run.clone(),
            Box::new(Fence(Arc::new(AtomicBool::new(false)))),
            move |stored, _| {
                assert_eq!(stored.bytes(Limits::default()).unwrap(), sink_bytes);
                Ok(())
            },
        )
        .await
        .unwrap();
    assert_ne!(receipt, original_pin);
    assert_eq!(run.replay().data().snapshot, original_pin);
    let p = b.issue_principal(run.owner().clone()).await.unwrap();
    let c = b.current(&p).await.unwrap();
    assert_eq!(
        b.reopen_v3(&p, &c, run.id()).await.unwrap_err().kind,
        ErrorKind::Denied
    );
    let mut replay_policy = b.policy_state().await.unwrap();
    replay_policy
        .principals
        .get_mut(run.owner())
        .unwrap()
        .1
        .insert(Iri::http(Operation::Replay.role()).unwrap());
    replay_policy.classes.remove(&optional);
    b.set_policy_state(
        &IdempotencyKey::new("v3-replay-grant").unwrap(),
        &replay_policy,
    )
    .await
    .unwrap();
    let c = b.current(&p).await.unwrap();
    let reopened = b.reopen_v3(&p, &c, run.id()).await.unwrap();
    assert_eq!(reopened.bytes(Limits::default()).unwrap(), original_bytes);
    let replay_authorization = b
        .prepare_recorded_replay(p.clone(), &c, run.id())
        .await
        .unwrap();
    assert_eq!(replay_authorization.principal(), run.owner());
    assert_eq!(replay_authorization.operation(), Operation::Replay);
    assert!(!replay_authorization
        .original_decision(&optional, None)
        .unwrap());
    assert_eq!(
        replay_authorization.run().bytes(Limits::default()).unwrap(),
        original_bytes
    );
    assert!(replay_authorization
        .original_decision(&ResourceId::new("unrecorded").unwrap(), None)
        .is_err());
    let retried = b
        .retry_original_v3(&p, &c, run.id(), run.operation_hash())
        .await
        .unwrap();
    assert_eq!(retried.bytes(Limits::default()).unwrap(), original_bytes);
    assert!(cdb_core::recording::RunEnvelope::from_record(
        &retried.to_record(Limits::default()).unwrap(),
        Limits::default(),
    )
    .is_err());

    let mut state = b.policy_state().await.unwrap();
    state.policy = cdb_core::policy::PolicySet::parse(
        format!(r#"{{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{{"@id":"https://test.example/allow","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true}},{{"@id":"https://test.example/deny-payload","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#onProperty":"{}","https://ns.flur.ee/db#allow":false}}]}}"#, RUN_PAYLOAD).as_bytes(),
        Limits::default(),
    ).unwrap();
    b.set_policy_state(&IdempotencyKey::new("v3-payload-deny").unwrap(), &state)
        .await
        .unwrap();
    let p = b.issue_principal(run.owner().clone()).await.unwrap();
    let c = b.current(&p).await.unwrap();
    assert_eq!(
        b.reopen_v3(&p, &c, run.id()).await.unwrap_err().kind,
        ErrorKind::Denied
    );
}

struct Fence(Arc<AtomicBool>);
impl ExternalPublicationFence for Fence {
    fn check(&self) -> Result<()> {
        if self.0.load(Ordering::SeqCst) {
            Err(Error::new(ErrorKind::Denied, "cancelled"))
        } else {
            Ok(())
        }
    }
}
