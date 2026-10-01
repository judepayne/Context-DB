use cdb_backend_fluree::{
    execution_authorization::ExecutionFence,
    policy::PolicyState,
    runs::{ExternalPublicationFence, Operation, ProtectedRun},
    AuthorityOptions, FlureeBackend,
};
use cdb_core::{
    artifact::ArtifactRef,
    canonical::CanonicalProjection,
    contracts::{CapturedSnapshot, ExecutionCaptures, PolicyService},
    id::*,
    recording::{
        RecordingEngine, ReplayData, ReplayDataInput, RunEnvelope, REQUIRED_SCOPES, RUN_PAYLOAD,
    },
    recording_v3::{ReplayDataV3, ReplayDataV3Input, RunEnvelopeV3, REPLAY_ABI},
    recording_v4::{
        PreparedSemanticMappingDescriptor, ReplayDataV4, RunEnvelopeV4, SemanticEvidenceV4,
        SemanticEvidenceV4Input, SemanticPolicyModeV4,
    },
    snapshot::{GraphPin, SnapshotRef},
    CanonicalValue as V, ErrorKind, Limits, Result, Timestamp,
};
use std::sync::Arc;

#[path = "../../cdb-core/tests/common/mod.rs"]
mod common;
use common::fixture;

fn options(path: &std::path::Path) -> AuthorityOptions {
    AuthorityOptions::new(
        path.join("db"),
        "run-versions:main".into(),
        BackendId::new("fluree").unwrap(),
        AuthorityId::new("owner").unwrap(),
        GraphId::new("graph").unwrap(),
    )
}

async fn setup() -> (tempfile::TempDir, Arc<FlureeBackend>) {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(FlureeBackend::create(options(dir.path())).await.unwrap());
    backend.bootstrap_governance().await.unwrap();
    let mut state = PolicyState::deny_all().unwrap();
    let alice_roles = [Operation::Query, Operation::Read, Operation::Replay]
        .into_iter()
        .map(|operation| Iri::http(operation.role()).unwrap())
        .collect();
    state
        .principals
        .insert(PrincipalId::new("alice").unwrap(), (true, alice_roles));
    state.principals.insert(
        PrincipalId::new("bob").unwrap(),
        (
            true,
            [Operation::Query, Operation::Read, Operation::Replay]
                .into_iter()
                .map(|operation| Iri::http(operation.role()).unwrap())
                .collect(),
        ),
    );
    state.policy = cdb_core::policy::PolicySet::parse(
        br#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{"@id":"https://test.example/allow","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true}]}"#,
        Limits::default(),
    )
    .unwrap();
    backend
        .set_policy_state(&IdempotencyKey::new("policy").unwrap(), &state)
        .await
        .unwrap();
    (dir, backend)
}

fn input(snapshot: cdb_core::snapshot::SnapshotRef) -> ReplayDataInput {
    let limits = Limits::default();
    let mut plan_value = fixture("plan");
    let V::Object(root) = &mut plan_value else {
        unreachable!()
    };
    let V::Object(payload) = root.get_mut("payload").unwrap() else {
        unreachable!()
    };
    let V::Object(artifacts) = payload.get_mut("artifacts").unwrap() else {
        unreachable!()
    };
    artifacts.insert("query".into(), artifacts["config"].clone());
    let plan =
        CanonicalProjection::read(&plan_value.canonical_bytes(limits).unwrap(), limits).unwrap();
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
        requested_snapshot: snapshot,
        as_of: cdb_core::Timestamp::parse("1969-12-31T23:59:59.999Z").unwrap(),
        stale: false,
        plan_hash: ContentHash::parse(
            "sha256:c62caf74fbecd39100be7fa9fbcbcea7f9c0bb84815814c125fcfc61bc9fe5a3",
        )
        .unwrap(),
        plan,
        response: CanonicalProjection::read(
            &fixture("response").canonical_bytes(limits).unwrap(),
            limits,
        )
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
            .map(|scope| ResourceId::new(*scope).unwrap())
            .collect(),
        functions: vec![],
    }
}

async fn v2(backend: &FlureeBackend, id: &str) -> RunEnvelope {
    RunEnvelope::new(
        RunId::new(id).unwrap(),
        PrincipalId::new("alice").unwrap(),
        ContentHash::of_bytes(b"v2-operation"),
        ReplayData::new(input(backend.head().await.unwrap()), Limits::default()).unwrap(),
        Limits::default(),
    )
    .unwrap()
}

async fn v3(backend: &FlureeBackend, id: &str) -> RunEnvelopeV3 {
    let mut base = input(backend.head().await.unwrap());
    base.replay_abi = VersionId::new(REPLAY_ABI).unwrap();
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
        ("policy".into(), V::Array(vec![])),
        (
            "scopes".into(),
            V::Array(
                base.scopes
                    .iter()
                    .map(|scope| V::string(scope.as_str()))
                    .collect(),
            ),
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

fn semantic_pin() -> SnapshotRef {
    SnapshotRef::new(
        BackendId::new("semantic").unwrap(),
        GraphPin::new(
            AuthorityId::new("semantic-authority").unwrap(),
            GraphId::new("semantic:main").unwrap(),
            VersionId::new("7").unwrap(),
            ResourceId::new("bafy-semantic-capture").unwrap(),
        ),
    )
}

fn semantic_evidence() -> SemanticEvidenceV4 {
    let capture = semantic_pin();
    let prepared = ContentHash::of_bytes(b"prepared");
    SemanticEvidenceV4::new(
        SemanticEvidenceV4Input {
            capture: capture.clone(),
            requested_as_of: None,
            policy_mode: SemanticPolicyModeV4::Unrestricted,
            policy_dependency_root: ContentHash::of_bytes(b"policy"),
            policy_source_observation: ResourceId::new("policy-observation").unwrap(),
            principal: PrincipalId::new("alice").unwrap(),
            action: Iri::new("urn:ctxql:view").unwrap(),
            historical_config_root: ContentHash::of_bytes(b"config"),
            graph_role_map_root: ContentHash::of_bytes(b"roles"),
            configuration_graph: Iri::new("urn:graph:config").unwrap(),
            governed_data_graphs: vec![Iri::new("urn:graph:data").unwrap()],
            claim_graphs: vec![],
            schema_source: Iri::new("urn:graph:schema").unwrap(),
            schema_graphs: vec![Iri::new("urn:graph:schema").unwrap()],
            follow_owl_imports: false,
            data_root: ContentHash::of_bytes(b"data"),
            schema_root: ContentHash::of_bytes(b"schema"),
            data_commitments: vec![],
            schema_commitments: vec![],
            visible_support_ids: vec![],
            authorized_data_quads: 0,
            authorized_schema_quads: 0,
            visible_supports: 0,
            authorized_premise_root: ContentHash::of_bytes(b"premises"),
            execution_manifest_root: ContentHash::of_bytes(b"manifest"),
            ontology_profile: VersionId::new("none/v1").unwrap(),
            full_ontology_bundle_root: ContentHash::of_bytes(b"ontology-bundle-none"),
            ontology_profile_result_root: ContentHash::of_bytes(b"ontology-profile-none"),
            reasoner_input_root: ContentHash::of_bytes(b"reasoner-input-none"),
            structural_mapping_algorithm: VersionId::new("none/v1").unwrap(),
            profile_limits_identity: ContentHash::of_bytes(b"profile-limits-none"),
            materialization_limits_identity: ContentHash::of_bytes(b"materialization-limits-none"),
            reasoning_limits_identity: ContentHash::of_bytes(b"reasoning-limits-none"),
            prepared_root: prepared.clone(),
            semantic_codec: VersionId::new("ctxql-semantic-rdf/v1").unwrap(),
            commitment_algorithm: VersionId::new("ctxql-source-quad-commitment/sha256-v1").unwrap(),
            extraction_algorithm: VersionId::new("ctxql-authorized-view-extraction/v1").unwrap(),
            materializer: VersionId::new("ctxql-authorized-view/no-sandbox-v1").unwrap(),
            reasoner: VersionId::new("none/v1").unwrap(),
            budget_identity: ContentHash::of_bytes(b"budget"),
            diagnostics_root: ContentHash::of_bytes(b"diagnostics"),
            completeness_selector: "complete".into(),
            completeness_evidence: ContentHash::of_bytes(b"complete"),
            mapping: PreparedSemanticMappingDescriptor::none(capture, prepared, Limits::default())
                .unwrap(),
            supported_subset: None,
        },
        Limits::default(),
    )
    .unwrap()
}

async fn v4(backend: &FlureeBackend, id: &str) -> RunEnvelopeV4 {
    let semantic = semantic_pin();
    let control = backend.head().await.unwrap();
    let mut base = input(semantic.clone());
    base.replay_abi = VersionId::new(REPLAY_ABI).unwrap();
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
        ("policy".into(), V::Array(vec![])),
        (
            "scopes".into(),
            V::Array(
                base.scopes
                    .iter()
                    .map(|scope| V::string(scope.as_str()))
                    .collect(),
            ),
        ),
        ("function_counts".into(), V::Array(vec![])),
    ])
    .unwrap();
    let executor = base.engine.clone();
    let base = ReplayDataV3::new(
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
    let captures = ExecutionCaptures::new(
        CapturedSnapshot {
            as_of: Timestamp::parse("1969-12-31T23:59:59.999Z").unwrap(),
            snapshot: semantic,
        },
        control,
    );
    let replay =
        ReplayDataV4::new(base, semantic_evidence(), &captures, Limits::default()).unwrap();
    RunEnvelopeV4::new(
        RunId::new(id).unwrap(),
        PrincipalId::new("alice").unwrap(),
        ContentHash::of_bytes(b"v4-operation"),
        replay,
        Limits::default(),
    )
    .unwrap()
}

struct Fence;
impl ExternalPublicationFence for Fence {
    fn check(&self) -> Result<()> {
        Ok(())
    }
}
impl ExecutionFence for Fence {
    fn check_disclosure(&self) -> Result<()> {
        Ok(())
    }
}

async fn commit_v2(backend: Arc<FlureeBackend>, run: RunEnvelope) {
    let principal = backend.issue_principal(run.owner().clone()).await.unwrap();
    let context = backend.current(&principal).await.unwrap();
    backend
        .guarded_owned_commit_record(principal, context, run, Box::new(Fence), |_, _| Ok(()))
        .await
        .unwrap();
}

async fn commit_v3(backend: Arc<FlureeBackend>, run: RunEnvelopeV3) {
    let execution = backend
        .capture_execution(
            backend.issue_principal(run.owner().clone()).await.unwrap(),
            run.replay().data().snapshot.clone(),
            run.replay().data().as_of,
            run.id().clone(),
            run.replay().data().plan_hash.clone(),
            Operation::Query,
        )
        .await
        .unwrap();
    for scope in &run.replay().data().scopes {
        assert!(backend
            .original_resource_allowed(&execution, scope)
            .unwrap());
    }
    backend
        .guarded_execution_commit_v3(
            execution.clone(),
            execution.release_footprint().unwrap(),
            run,
            Box::new(Fence),
            |_, _| Ok(()),
        )
        .await
        .unwrap();
}

async fn commit_v4(backend: Arc<FlureeBackend>, run: RunEnvelopeV4) {
    let principal = backend.issue_principal(run.owner().clone()).await.unwrap();
    backend
        .guarded_owned_commit_record_v4(principal, run, Box::new(Fence), |_, _| Ok(()))
        .await
        .unwrap();
}

#[test]
fn protected_dispatches_v2_v3_and_v4_without_caller_version_hint() {
    on_large_stack(protected_dispatch_check());
}

async fn protected_dispatch_check() {
    let (_dir, backend) = setup().await;
    let run_v2 = v2(&backend, "dispatch-v2").await;
    let run_v3 = v3(&backend, "dispatch-v3").await;
    let run_v4 = v4(&backend, "dispatch-v4").await;
    commit_v2(backend.clone(), run_v2.clone()).await;
    commit_v3(backend.clone(), run_v3.clone()).await;
    commit_v4(backend.clone(), run_v4.clone()).await;
    let principal = backend
        .issue_principal(PrincipalId::new("alice").unwrap())
        .await
        .unwrap();
    let context = backend.current(&principal).await.unwrap();

    assert_eq!(
        backend
            .guarded_find_versioned_run(&principal, &context, run_v2.id(), Operation::Query)
            .await
            .unwrap(),
        Some(ProtectedRun::V2(run_v2.clone()))
    );
    assert_eq!(
        backend
            .guarded_find_versioned_run(&principal, &context, run_v3.id(), Operation::Replay)
            .await
            .unwrap(),
        Some(ProtectedRun::V3(run_v3.clone()))
    );
    assert_eq!(
        backend
            .guarded_find_versioned_run(&principal, &context, run_v4.id(), Operation::Replay)
            .await
            .unwrap(),
        Some(ProtectedRun::V4(run_v4.clone()))
    );
    assert_eq!(
        backend
            .guarded_v4_run_for(&principal, &context, run_v2.id(), Operation::Read)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Invalid
    );
    assert_eq!(
        backend
            .guarded_v4_run_for(&principal, &context, run_v3.id(), Operation::Read)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Invalid
    );
    assert_eq!(
        backend
            .guarded_v3_run_for(&principal, &context, run_v4.id(), Operation::Read)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Invalid
    );
    assert!(backend
        .guarded_find_versioned_run(
            &principal,
            &context,
            &RunId::new("absent").unwrap(),
            Operation::Query,
        )
        .await
        .unwrap()
        .is_none());
}

#[test]
fn v4_retry_survives_restart_preserves_dual_captures_and_rechecks_revocation() {
    on_large_stack(v4_restart_retry_check());
}

async fn v4_restart_retry_check() {
    let (dir, backend) = setup().await;
    let run = v4(&backend, "v4-restart-retry").await;
    let semantic_capture = run.replay().semantic().capture(Limits::default()).unwrap();
    let control_capture = run.replay().control_capture().clone();
    assert_ne!(semantic_capture, control_capture);
    commit_v4(backend.clone(), run.clone()).await;
    drop(backend);

    let backend = Arc::new(FlureeBackend::open(options(dir.path())).await.unwrap());
    let principal = backend
        .issue_principal(PrincipalId::new("alice").unwrap())
        .await
        .unwrap();
    let (retried, receipt) = backend
        .retry_original_v4_with_receipt(&principal, run.id(), run.operation_hash())
        .await
        .unwrap();
    assert_eq!(retried, run);
    assert_eq!(
        retried
            .replay()
            .semantic()
            .capture(Limits::default())
            .unwrap(),
        semantic_capture
    );
    assert_eq!(retried.replay().control_capture(), &control_capture);
    assert_eq!(receipt, backend.head().await.unwrap());

    backend
        .set_policy_state(
            &IdempotencyKey::new("v4-revoke").unwrap(),
            &PolicyState::deny_all().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        backend
            .retry_original_v4_with_receipt(&principal, run.id(), run.operation_hash())
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Denied
    );
}

#[test]
fn descriptor_payload_and_foreign_owner_are_denied() {
    on_large_stack(protected_denials_check());
}

async fn protected_denials_check() {
    let (_dir, backend) = setup().await;
    let run = v2(&backend, "protected-denials").await;
    commit_v2(backend.clone(), run.clone()).await;

    let bob = backend
        .issue_principal(PrincipalId::new("bob").unwrap())
        .await
        .unwrap();
    let bob_context = backend.current(&bob).await.unwrap();
    assert_eq!(
        backend
            .guarded_find_versioned_run(&bob, &bob_context, run.id(), Operation::Query)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Denied
    );

    let mut state = backend.policy_state().await.unwrap();
    state.policy = cdb_core::policy::PolicySet::parse(
        format!(r#"{{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{{"@id":"https://test.example/allow","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true}},{{"@id":"https://test.example/deny-payload","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#onProperty":"{RUN_PAYLOAD}","https://ns.flur.ee/db#allow":false}}]}}"#).as_bytes(),
        Limits::default(),
    ).unwrap();
    backend
        .set_policy_state(&IdempotencyKey::new("deny-payload").unwrap(), &state)
        .await
        .unwrap();
    let alice = backend
        .issue_principal(PrincipalId::new("alice").unwrap())
        .await
        .unwrap();
    let context = backend.current(&alice).await.unwrap();
    assert_eq!(
        backend
            .guarded_find_versioned_run(&alice, &context, run.id(), Operation::Read)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Denied
    );

    state.policy = cdb_core::policy::PolicySet::parse(
        format!(r#"{{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{{"@id":"https://test.example/payload-only","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#onProperty":"{RUN_PAYLOAD}","https://ns.flur.ee/db#allow":true}}]}}"#).as_bytes(),
        Limits::default(),
    ).unwrap();
    backend
        .set_policy_state(&IdempotencyKey::new("deny-descriptor").unwrap(), &state)
        .await
        .unwrap();
    let context = backend.current(&alice).await.unwrap();
    assert_eq!(
        backend
            .guarded_find_versioned_run(&alice, &context, run.id(), Operation::Read)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Denied
    );
}

fn on_large_stack(future: impl std::future::Future<Output = ()> + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(future)
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn schema_corruption_is_an_error_not_version_absence() {
    on_large_stack(schema_corruption_check());
}

async fn schema_corruption_check() {
    let (_dir, backend) = setup().await;
    let run = v2(&backend, "corrupt-schema").await;
    let mut value = run.projection();
    let V::Object(object) = &mut value else {
        unreachable!()
    };
    object.insert("schema".into(), V::string("ctxql-recorded-run/corrupt"));
    let error = RunEnvelope::from_value(&value, Limits::default()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Invalid);
}
