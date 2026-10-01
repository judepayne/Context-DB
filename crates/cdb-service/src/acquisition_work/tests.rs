use super::*;
use crate::{acquisition_v2_fixture::AcquisitionV2Fixture, graph_query::GraphQueryLimits, Service};
use cdb_core::{
    acquisition::SourceObjectWriter,
    artifact::ArtifactRef,
    contracts::IoFuture,
    evidence::EvidenceSelector,
    id::{BundleId, ClaimId, IdempotencyKey, Iri, SourceId, VersionId},
    review::{ReviewAssertionIntent, VocabularyVerdict},
    semantic_admission::stable_acquisition_v2_claim_id,
    source::SourceReadRequest,
};
use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[test]
fn artifact_pages_preserve_utf8_and_exact_bytes() {
    let text = format!(
        "{}🙂é終{}",
        "x".repeat(ARTIFACT_PAGE_TARGET_BYTES - 1),
        "z".repeat(30)
    );
    let pages = utf8_artifact_pages(text.as_bytes(), ARTIFACT_PAGE_TARGET_BYTES).unwrap();
    assert_eq!(pages.len(), 2);
    assert!(pages
        .iter()
        .all(|page| page.len() <= ARTIFACT_PAGE_TARGET_BYTES && std::str::from_utf8(page).is_ok()));
    assert_eq!(pages.concat(), text.as_bytes());
    assert!(utf8_artifact_pages("🙂".as_bytes(), 3).is_err());
    assert!(utf8_artifact_pages(&[0xff], 4).is_err());
}

struct FailNthPut {
    inner: Arc<dyn SourceObjectWriter>,
    calls: Arc<AtomicUsize>,
    fail_at: usize,
}

impl SourceObjectWriter for FailNthPut {
    fn put<'a>(&'a self, bytes: &'a [u8], max_bytes: usize) -> IoFuture<'a, ContentHash> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_at {
            return Box::pin(async {
                Err(Error::new(
                    ErrorKind::Backend,
                    "injected result artifact publication failure",
                ))
            });
        }
        self.inner.put(bytes, max_bytes)
    }
}

fn stable_claim() -> CandidateClaim {
    let mut value = V::parse(
        br#"{"claim_id":"urn:ctxql:claim:v2:placeholder","claim_type":"urn:type:claim","confidence":1,"ext":{"ctxql.acquisition.v2/claim_identity":"stable-component/v1","ctxql.acquisition.v2/component_ref":"window:recovery#attribute:amount"},"grounding_level":"claim_only","lineage":{"schema":"ctxql.lineage.v1","sources":[]},"object_id":{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#integer","value":42,"language":null},"object_type":"http://www.w3.org/2001/XMLSchema#integer","relation":"urn:relation:count","relation_type":"urn:type:relation","subject_id":"urn:subject:recovery","subject_type":"urn:type:entity"}"#,
        Limits::default(),
    )
    .unwrap();
    let provisional = CandidateClaim::from_value(&value).unwrap();
    let id = stable_acquisition_v2_claim_id(&provisional, Limits::default()).unwrap();
    let V::Object(fields) = &mut value else {
        unreachable!()
    };
    fields.insert("claim_id".into(), V::string(id.as_str()));
    CandidateClaim::from_value(&value).unwrap()
}

async fn freeze_draft(service: &AcquisitionService, job: &JobId) -> ClaimId {
    freeze_draft_with_report(service, job, V::object([]).unwrap()).await
}

async fn recovery_draft(service: &AcquisitionService, job: &JobId, report: V) -> (V, ClaimId) {
    let claim = stable_claim();
    let claim_id = claim.id().clone();
    let review = ValidatedReviewBundle::new(
        BundleId::new("bundle:review:recovery").unwrap(),
        "evaluation:recovery",
        job.as_str(),
        AttemptId::new("attempt:recovery").unwrap(),
        service
            .current_catalog()
            .await
            .unwrap()
            .identity()
            .capture()
            .clone(),
        vec![ReviewRecord::new(
            ReviewRecordId::new("urn:ctxql:review:recovery").unwrap(),
            "window:recovery#attribute:amount",
            "urn:source:recovery",
            ContentHash::of_bytes(b"frozen review artifact"),
            VocabularyVerdict::Valid,
            ReviewAssertionIntent::Direct,
            vec!["accepted".into()],
            vec!["count".into()],
            vec!["entity".into()],
            vec!["urn:relation:count".into()],
            vec!["urn:type:entity".into()],
            vec![claim_id.clone()],
        )
        .unwrap()],
        Limits::default(),
    )
    .unwrap();
    let draft = V::object([
        ("schema".into(), V::string("ctxql-acquisition-work/v1")),
        ("job_id".into(), V::string(job.as_str())),
        ("review".into(), review.projection()),
        ("claims".into(), V::Array(vec![claim.projection()])),
        ("assertions".into(), V::string("accepted")),
        ("ontology_mode".into(), V::string("direct")),
        ("extraction_run".into(), V::string("extraction:recovery")),
        ("report".into(), report),
    ])
    .unwrap();
    (draft, claim_id)
}

async fn freeze_draft_with_report(service: &AcquisitionService, job: &JobId, report: V) -> ClaimId {
    let (draft, claim_id) = recovery_draft(service, job, report).await;
    service
        .seal_work_value(job, "evaluation", &draft)
        .await
        .unwrap();
    claim_id
}

async fn freeze_graph_draft(
    service: &AcquisitionService,
    job: &JobId,
    dependencies: BTreeSet<String>,
) -> ClaimId {
    let capture = V::string("provider graph capture");
    let capture_root = service
        .seal_work_value(job, "capture", &capture)
        .await
        .unwrap();
    let workspace = V::string("frozen graph workspace");
    let workspace_root = service
        .seal_work_value(job, "graph_workspace", &workspace)
        .await
        .unwrap();
    let context = V::string("frozen graph context");
    let context_root = service
        .seal_work_value(job, "graph_context", &context)
        .await
        .unwrap();
    let query_config = ArtifactRef::new(
        Iri::new("https://test/graph-recovery-config").unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(
            include_str!("../../../../fixtures/conformance/p2/config.json").as_bytes(),
        ),
    );
    let capability = V::object([
        ("query_config".into(), query_config.projection()),
        ("profile_selector".into(), V::Null),
        ("profile".into(), V::Null),
    ])
    .unwrap();
    let capability_root = service
        .seal_work_value(job, "graph_capability", &capability)
        .await
        .unwrap();
    let leaf_roots = V::Array(Vec::new());
    let transcript_root =
        ContentHash::of_bytes(&leaf_roots.canonical_bytes(Limits::default()).unwrap());
    let index = V::object([
        ("schema".into(), V::string("ctxql-graph-capture-index/v1")),
        ("stable_session_seed".into(), V::string("recovery-session")),
        (
            "capability_summary_root".into(),
            V::string(capability_root.as_str()),
        ),
        ("semantic_snapshot".into(), V::string("frozen-snapshot")),
        ("source_version".into(), V::string("frozen-source-version")),
        ("source_range_root".into(), V::string("frozen-range-root")),
        ("leaf_roots".into(), leaf_roots.clone()),
        (
            "transcript_root".into(),
            V::string(transcript_root.as_str()),
        ),
        (
            "final_workspace_root".into(),
            V::string(workspace_root.as_str()),
        ),
        (
            "graph_context_root".into(),
            V::string(context_root.as_str()),
        ),
        ("final_revision".into(), V::integer(0)),
        (
            "claim_dependencies".into(),
            V::Array(dependencies.iter().map(V::string).collect()),
        ),
    ])
    .unwrap();
    let graph_capture_root = service
        .seal_work_value(job, "graph_capture", &index)
        .await
        .unwrap();
    let (mut draft, claim_id) = recovery_draft(service, job, V::object([]).unwrap()).await;
    let V::Object(fields) = &mut draft else {
        unreachable!()
    };
    fields.insert(
        "schema".into(),
        V::string("ctxql-acquisition-graph-work/v1"),
    );
    fields.insert(
        "graph".into(),
        V::object([
            (
                "capture_root".into(),
                V::string(graph_capture_root.as_str()),
            ),
            ("context_root".into(), V::string(context_root.as_str())),
            ("workspace_root".into(), V::string(workspace_root.as_str())),
            (
                "capability_root".into(),
                V::string(capability_root.as_str()),
            ),
            ("leaf_roots".into(), leaf_roots),
        ])
        .unwrap(),
    );
    fields.insert("graph_artifact_descriptors".into(), V::Array(Vec::new()));
    service
        .seal_work_value(job, "evaluation", &draft)
        .await
        .unwrap();
    assert_eq!(
        service
            .frozen_graph_dependencies(job, &draft)
            .await
            .unwrap(),
        dependencies
    );
    assert_eq!(
        service.work.get(job, "capture").unwrap(),
        Some(capture_root)
    );
    claim_id
}

async fn graph_host(
    fixture: &AcquisitionV2Fixture,
) -> (Arc<AcquisitionService>, Arc<GraphQueryHost>, ArtifactRef) {
    let config_bytes = include_str!("../../../../fixtures/conformance/p2/config.json");
    let config_hash = ContentHash::of_bytes(config_bytes.as_bytes());
    let config_ref = ArtifactRef::new(
        Iri::new("https://test/graph-recovery-config").unwrap(),
        VersionId::new("1").unwrap(),
        config_hash.clone(),
    );
    let token = std::fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    let publisher = Service::open(fixture.config().unwrap()).await.unwrap();
    publisher
        .dispatch(
            &token,
            &serde_json::to_vec(&serde_json::json!({
                "schema":"ctxql-service/v1",
                "op":"publish",
                "artifact": {
                    "iri": config_ref.iri().as_str(),
                    "version": config_ref.version().as_str(),
                    "hash": config_hash.as_str()
                },
                "content": config_bytes
            }))
            .unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    publisher.shutdown().await.unwrap();
    drop(publisher);
    let service = AcquisitionService::open(
        &fixture.config().unwrap(),
        fixture.catalog_identity().clone(),
    )
    .await
    .unwrap();
    let host = service
        .graph_query_host(config_ref.clone(), None, GraphQueryLimits::default())
        .await
        .unwrap();
    (service, host, config_ref)
}

#[tokio::test]
async fn source_revocation_between_initial_authorization_and_resume_blocks_mutation_and_release() {
    use crate::sources::{selector_records, AuthorizedSources, SourceAuthorization, SourceStore};
    use cdb_core::admission::{AdmissionBatch, ExportRecord, ResourceChange};
    use cdb_core::id::PrincipalId;
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let (service, host, _) = graph_host(&fixture).await;
    let job = JobId::new("job:source-fenced-resume").unwrap();
    freeze_graph_draft(&service, &job, BTreeSet::new()).await;
    let store = Arc::new(SourceStore::open(fixture.root().join("sources"), 4096).unwrap());
    let text = b"retained source";
    let version = store.put(text).unwrap();
    let request = SourceReadRequest {
        source_id: SourceId::new("urn:source:recovery").unwrap(),
        version,
        selector: EvidenceSelector::WholeDocument,
        max_bytes: text.len(),
    };
    let records = selector_records(&request, &ContentHash::of_bytes(text))
        .unwrap()
        .into_iter()
        .map(|record| {
            let ExportRecord::Resource(record) = record else {
                panic!("source selector resource")
            };
            ResourceChange::Add(record)
        })
        .collect();
    let batch = AdmissionBatch::new(
        vec![],
        vec![],
        records,
        vec![],
        V::object([]).unwrap(),
        Limits::default(),
    )
    .unwrap();
    GraphBackend::admit(
        service.authority.as_ref(),
        &IdempotencyKey::new("source-fence-selectors").unwrap(),
        &batch,
    )
    .await
    .unwrap();
    let principal_id =
        PrincipalId::new(cdb_backend_fluree::official_bootstrap::ACQUISITION_V2_FIXTURE_PRINCIPAL)
            .unwrap();
    let principal = service
        .authority
        .issue_principal(principal_id.clone())
        .await
        .unwrap();
    let sources = AuthorizedSources::new(
        service.authority.clone(),
        service.authority.clone(),
        Arc::new(principal),
        store,
    );
    sources
        .bind_snapshot(
            &GraphBackend::head(service.authority.as_ref())
                .await
                .unwrap(),
        )
        .unwrap();
    let grant = sources.authorize(&request).await.unwrap();
    let mut scope = SourceAuthorization::default();
    scope.extend(&grant).unwrap();
    let host = host.with_source_authority(scope);
    let head_before = service
        .semantic_writer
        .session()
        .await
        .capture_current()
        .await
        .unwrap();
    let ready = Arc::new(tokio::sync::Notify::new());
    let proceed = Arc::new(tokio::sync::Notify::new());
    let task = {
        let service = service.clone();
        let host = host.clone();
        let job = job.clone();
        let ready = ready.clone();
        let proceed = proceed.clone();
        tokio::spawn(async move {
            // The exact source grant has already been checked. Keep the request
            // in flight here so revocation wins before its mutation gate.
            ready.notify_one();
            proceed.notified().await;
            service
                .complete_work_guarded_dependencies(
                    &job,
                    WaitPoint::Admitted,
                    host,
                    BTreeSet::new(),
                    Instant::now() + Duration::from_secs(20),
                )
                .await
        })
    };
    ready.notified().await;
    let mut policy = service.authority.policy_state().await.unwrap();
    policy
        .principals
        .get_mut(&principal_id)
        .unwrap()
        .1
        .remove(&Iri::new("https://ctxql.org/roles/serviceReader").unwrap());
    service
        .authority
        .set_policy_state(
            &IdempotencyKey::new("source-fence-revoke").unwrap(),
            &policy,
        )
        .await
        .unwrap();
    proceed.notify_one();
    assert_eq!(
        task.await
            .unwrap()
            .err()
            .expect("revoked source must deny resume")
            .kind,
        ErrorKind::Denied
    );
    assert_eq!(
        service
            .semantic_writer
            .session()
            .await
            .capture_current()
            .await
            .unwrap(),
        head_before
    );
    assert!(service
        .control
        .review_prepared_records()
        .await
        .unwrap()
        .is_empty());
    let released = Arc::new(AtomicBool::new(false));
    let sink = released.clone();
    let error = host
        .guarded_disclosure_action(
            BTreeSet::new(),
            Arc::new(AtomicBool::new(false)),
            Instant::now() + Duration::from_secs(20),
            move || async move {
                sink.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Denied);
    assert!(
        !released.load(Ordering::SeqCst),
        "revoked source must not reach final publication sink"
    );
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn frozen_graph_dependencies_survive_reopen_and_cannot_be_omitted() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let config = fixture.config().unwrap();
    let job = JobId::new("job:graph-dependencies-reopen").unwrap();
    let missing = "urn:ctxql:claim:revoked-dependency".to_owned();
    let dependencies = BTreeSet::from([missing]);
    let (service, host, config_ref) = graph_host(&fixture).await;
    freeze_graph_draft(&service, &job, dependencies.clone()).await;
    drop(host);
    service.shutdown().await.unwrap();
    drop(service);

    let reopened = AcquisitionService::open(&config, fixture.catalog_identity().clone())
        .await
        .unwrap();
    let draft = reopened
        .work_value(&job, "evaluation")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        reopened
            .frozen_graph_dependencies(&job, &draft)
            .await
            .unwrap(),
        dependencies,
        "the immutable capture index remains the dependency authority after reopen"
    );
    let host = reopened
        .graph_query_host(config_ref, None, GraphQueryLimits::default())
        .await
        .unwrap();
    let error = reopened
        .complete_work_guarded_dependencies(
            &job,
            WaitPoint::Admitted,
            host,
            BTreeSet::new(),
            Instant::now() + Duration::from_secs(20),
        )
        .await
        .err()
        .expect("omitted frozen dependency must be denied");
    assert_eq!(error.kind, ErrorKind::Denied);
    assert_eq!(
        error.message,
        "graph acquisition dependency binding mismatch"
    );
    assert!(reopened
        .control
        .review_prepared_records()
        .await
        .unwrap()
        .is_empty());
    assert!(reopened
        .control
        .prepared_records()
        .await
        .unwrap()
        .is_empty());
    assert!(reopened.work.get(&job, "result").unwrap().is_none());
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn committed_graph_receipt_survives_revocation_while_republication_is_denied() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let job = JobId::new("job:graph-committed-receipt-revocation").unwrap();
    let (service, host, _) = graph_host(&fixture).await;
    let claim_id = freeze_graph_draft(&service, &job, BTreeSet::new()).await;
    let completed = service
        .complete_work_guarded_dependencies(
            &job,
            WaitPoint::Admitted,
            host.clone(),
            BTreeSet::new(),
            Instant::now() + Duration::from_secs(20),
        )
        .await
        .unwrap();
    let receipt = completed.business.expect("graph-backed business receipt");
    assert_eq!(receipt.claim_ids(), std::slice::from_ref(&claim_id));
    let pending_job = JobId::new("job:graph-new-admission-after-revocation").unwrap();
    freeze_graph_draft(&service, &pending_job, BTreeSet::new()).await;
    let prepared = service
        .control
        .prepared_records()
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.job_id == job)
        .unwrap();

    let original_policy = service.authority.policy_state().await.unwrap();
    let mut revoked = original_policy.clone();
    revoked
        .principals
        .get_mut(
            &cdb_core::id::PrincipalId::new(
                cdb_backend_fluree::official_bootstrap::ACQUISITION_V2_FIXTURE_PRINCIPAL,
            )
            .unwrap(),
        )
        .unwrap()
        .0 = false;
    service
        .authority
        .set_policy_state(
            &IdempotencyKey::new("graph-work-revoke-query").unwrap(),
            &revoked,
        )
        .await
        .unwrap();

    let denied_admission = service
        .complete_work_guarded_dependencies(
            &pending_job,
            WaitPoint::Admitted,
            host.clone(),
            BTreeSet::new(),
            Instant::now() + Duration::from_secs(20),
        )
        .await
        .err()
        .expect("revoked graph admission must be denied");
    assert_eq!(denied_admission.kind, ErrorKind::Denied);
    assert!(!service
        .control
        .prepared_records()
        .await
        .unwrap()
        .iter()
        .any(|record| record.job_id == pending_job));

    let denied_publication = service
        .complete_work_guarded_dependencies(
            &job,
            WaitPoint::Admitted,
            host,
            BTreeSet::new(),
            Instant::now() + Duration::from_secs(20),
        )
        .await
        .err()
        .expect("revoked graph publication must be denied");
    assert_eq!(denied_publication.kind, ErrorKind::Denied);
    assert_eq!(
        service
            .control
            .admission(&prepared.bundle_id)
            .await
            .unwrap()
            .unwrap()
            .projection(),
        receipt.projection(),
        "revocation denies a new release but cannot erase the exact business commit"
    );
    assert_eq!(
        service
            .control
            .prepared_records()
            .await
            .unwrap()
            .into_iter()
            .filter(|record| record.job_id == job)
            .count(),
        1,
        "denied republication cannot create a successor or duplicate commit"
    );
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn graph_backed_stale_absent_review_reauthorizes_before_successor_commit() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let job = JobId::new("job:graph-stale-absent-review").unwrap();
    let (service, host, _) = graph_host(&fixture).await;
    freeze_graph_draft(&service, &job, BTreeSet::new()).await;
    let stale = seal_initial_review_attempt(&service, &job).await;
    commit_intervening_review(&service).await;

    let completed = service
        .complete_work_guarded_dependencies(
            &job,
            WaitPoint::Admitted,
            host,
            BTreeSet::new(),
            Instant::now() + Duration::from_secs(20),
        )
        .await
        .unwrap();
    assert!(completed.business.is_some());
    let superseded = service
        .control
        .superseded_absent_records()
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.predecessor_bundle_id == *stale.id())
        .expect("graph-backed review successor proof");
    assert_eq!(superseded.kind, SupersededPreparedKind::Review);
    assert!(service
        .control
        .review_admission(stale.id())
        .await
        .unwrap()
        .is_none());
    assert!(service
        .control
        .review_admission(&superseded.successor_bundle_id)
        .await
        .unwrap()
        .is_some());
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn graph_backed_stale_absent_business_reauthorizes_before_successor_commit() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let job = JobId::new("job:graph-stale-absent-business").unwrap();
    let (service, host, _) = graph_host(&fixture).await;
    let claim_id = freeze_graph_draft(&service, &job, BTreeSet::new()).await;
    let stale = seal_initial_business_attempt(&service, &job).await;

    let completed = service
        .complete_work_guarded_dependencies(
            &job,
            WaitPoint::Admitted,
            host,
            BTreeSet::new(),
            Instant::now() + Duration::from_secs(20),
        )
        .await
        .unwrap();
    assert_eq!(
        completed.business.as_ref().unwrap().claim_ids(),
        std::slice::from_ref(&claim_id)
    );
    let superseded = service
        .control
        .superseded_absent_records()
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.predecessor_bundle_id == *stale.id())
        .expect("graph-backed business successor proof");
    assert_eq!(superseded.kind, SupersededPreparedKind::Business);
    assert!(service
        .control
        .admission(stale.id())
        .await
        .unwrap()
        .is_none());
    assert!(service
        .control
        .admission(&superseded.successor_bundle_id)
        .await
        .unwrap()
        .is_some());
    service.shutdown().await.unwrap();
}

async fn seal_initial_review_attempt(
    service: &AcquisitionService,
    job: &JobId,
) -> ValidatedReviewBundle {
    let draft = service
        .work_value(job, "evaluation")
        .await
        .unwrap()
        .unwrap();
    let frozen =
        ValidatedReviewBundle::from_value(draft.field("review").unwrap(), Limits::default())
            .unwrap();
    let records = frozen
        .records()
        .iter()
        .map(|record| {
            let mut value = record.projection();
            let V::Object(fields) = &mut value else {
                unreachable!()
            };
            fields.insert("accepted_claim_ids".into(), V::Array(vec![]));
            ReviewRecord::from_value(&value).unwrap()
        })
        .collect();
    let session = service.semantic_writer.session().await;
    let bundle = ValidatedReviewBundle::new(
        frozen.id().clone(),
        frozen.evaluation_id(),
        frozen.logical_bundle_key(),
        frozen.attempt_id().clone(),
        session.capture_current().await.unwrap(),
        records,
        Limits::default(),
    )
    .unwrap();
    drop(session);
    service
        .seal_work_value(job, "review", &bundle.projection())
        .await
        .unwrap();
    let prepared = ReviewBundlePrepared::new(job.clone(), &bundle, work_timestamp().unwrap());
    service
        .control
        .append_review_prepared(&prepared)
        .await
        .unwrap();
    bundle
}

async fn seal_initial_business_attempt(
    service: &AcquisitionService,
    job: &JobId,
) -> ValidatedSemanticBundle {
    let claim = stable_claim();
    let session = service.semantic_writer.session().await;
    let bundle = ValidatedSemanticBundle::new(
        BundleId::new("bundle:business:stale-checkpoint").unwrap(),
        ExtractionRunId::new("extraction:recovery").unwrap(),
        session.capture_current().await.unwrap(),
        V::object([
            (
                "schema".into(),
                V::string("ctxql-extraction-admission-descriptor/v2"),
            ),
            ("evaluation_id".into(), V::string("evaluation:recovery")),
            (
                "review_payload_root".into(),
                V::string(ContentHash::of_bytes(b"pending review").as_str()),
            ),
            ("ontology_mode".into(), V::string("direct")),
        ])
        .unwrap(),
        vec![("v2:recovery".into(), claim)],
        Limits::default(),
    )
    .unwrap();
    drop(session);
    service
        .seal_work_value(
            job,
            "business",
            &V::object([
                (
                    "backend".into(),
                    V::string(bundle.validation_capture().backend().as_str()),
                ),
                ("bundle".into(), bundle.projection()),
            ])
            .unwrap(),
        )
        .await
        .unwrap();
    let prepared = BundlePrepared {
        job_id: job.clone(),
        attempt_id: bundle_attempt_id(&bundle).unwrap(),
        bundle_id: bundle.id().clone(),
        admission_key: bundle.admission_key().as_str().to_owned(),
        descriptor_root: bundle.descriptor_root().clone(),
        payload_root: bundle.payload_root().clone(),
        canonical_claim_root: bundle.canonical_claim_root().clone(),
        expected_claim_ids: bundle.expected_claim_ids(),
        validation_capture: bundle.validation_capture().clone(),
        source_selector_root: service.work.get(job, "evaluation").unwrap().unwrap(),
        safe_counts: V::object([("claims".into(), V::integer(1))]).unwrap(),
        recorded_at: work_timestamp().unwrap(),
    };
    service.control.append_prepared(&prepared).await.unwrap();
    bundle
}

async fn commit_intervening_review(service: &AcquisitionService) {
    let session = service.semantic_writer.session().await;
    let bundle = ValidatedReviewBundle::new(
        BundleId::new("bundle:review:intervening").unwrap(),
        "evaluation:intervening",
        "job:intervening",
        AttemptId::new("attempt:intervening").unwrap(),
        session.capture_current().await.unwrap(),
        vec![ReviewRecord::new(
            ReviewRecordId::new("urn:ctxql:review:intervening").unwrap(),
            "window:intervening",
            "urn:source:intervening",
            ContentHash::of_bytes(b"intervening review artifact"),
            VocabularyVerdict::Valid,
            ReviewAssertionIntent::None,
            vec!["evidence_only".into()],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        )
        .unwrap()],
        Limits::default(),
    )
    .unwrap();
    service
        .commit_work_review(&JobId::new("job:intervening").unwrap(), &session, &bundle)
        .await
        .unwrap();
}

async fn assert_successor_result(
    service: &AcquisitionService,
    job: &JobId,
    result: &WorkOutcome,
    frozen_review_id: &str,
    claim_id: &ClaimId,
) {
    assert!(result.publication_error.is_none());
    let root = result.result_root.as_ref().expect("published result root");
    let receipt = result
        .result_review
        .as_ref()
        .expect("successor review receipt");
    assert_eq!(receipt.review_ids().len(), 1);
    assert_ne!(receipt.review_ids()[0].as_str(), frozen_review_id);
    assert_eq!(
        result.business.as_ref().unwrap().claim_ids(),
        std::slice::from_ref(claim_id)
    );

    let published = service.work_value(job, "result").await.unwrap().unwrap();
    assert_eq!(
        published.field("schema").unwrap().as_str().unwrap(),
        "ctxql-extraction-admission-result/v2"
    );
    assert_eq!(
        published.field("supersedes_review_ids").unwrap(),
        &V::Array(vec![V::string(frozen_review_id)])
    );
    let successor = ValidatedReviewBundle::from_value(
        &service
            .work_value(job, "result_review")
            .await
            .unwrap()
            .unwrap(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(successor.records().len(), 1);
    assert_eq!(successor.records()[0].artifact_root(), root);
    assert_eq!(
        successor.records()[0].accepted_claim_ids(),
        std::slice::from_ref(claim_id)
    );
}

#[tokio::test]
async fn frozen_work_completes_review_and_business_idempotently_after_reopen() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let config = fixture.config().unwrap();
    let job = JobId::new("job:work-recovery-idempotent").unwrap();
    let service = AcquisitionService::open(&config, fixture.catalog_identity().clone())
        .await
        .unwrap();
    let claim_id = freeze_draft(&service, &job).await;

    let completed = service
        .complete_work(&job, WaitPoint::Admitted)
        .await
        .unwrap();
    let first_business = completed.business.as_ref().unwrap().projection();
    assert_successor_result(
        &service,
        &job,
        &completed,
        "urn:ctxql:review:recovery",
        &claim_id,
    )
    .await;
    assert_eq!(fixture.pi_invocations().unwrap(), 0);

    service.shutdown().await.unwrap();
    drop(service);
    let reopened = AcquisitionService::open(&config, fixture.catalog_identity().clone())
        .await
        .unwrap();
    let repeated = reopened
        .complete_work(&job, WaitPoint::Admitted)
        .await
        .unwrap();

    assert_eq!(
        repeated.business.as_ref().unwrap().projection(),
        first_business
    );
    assert_eq!(repeated.result_root, completed.result_root);
    assert_eq!(
        repeated.result_review.as_ref().unwrap().projection(),
        completed.result_review.as_ref().unwrap().projection()
    );
    assert_eq!(fixture.pi_invocations().unwrap(), 0);
    assert_eq!(
        reopened
            .control
            .prepared_records()
            .await
            .unwrap()
            .iter()
            .filter(|prepared| prepared.job_id == job)
            .count(),
        1,
        "reopen must not create a duplicate business transaction"
    );
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn admission_rechecks_established_classification_support() {
    use cdb_core::classification::*;
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let service = AcquisitionService::open(
        &fixture.config().unwrap(),
        fixture.catalog_identity().clone(),
    )
    .await
    .unwrap();
    let job = JobId::new("job:classification-support-denial").unwrap();
    freeze_draft(&service, &job).await;
    let draft = service
        .work_value(&job, "evaluation")
        .await
        .unwrap()
        .unwrap();
    let claim =
        CandidateClaim::from_value(&draft.field("claims").unwrap().as_array().unwrap()[0]).unwrap();
    let subject = EndpointClassification::new(
        EndpointClassificationStatus::Classified,
        vec![ClassificationRef::new(
            claim.subject_type().clone(),
            ClassificationOrigin::Established,
            cdb_core::id::ResourceId::new("urn:missing:type-support").unwrap(),
        )],
    )
    .unwrap();
    let object =
        EndpointClassification::new(EndpointClassificationStatus::Unclassified, vec![]).unwrap();
    let metadata =
        ClassificationMetadata::new(ContentHash::of_bytes(b"frozen context"), subject, object);
    let mut value = claim.projection().as_object().unwrap().clone();
    let mut ext = claim.ext().as_object().unwrap().clone();
    ext.insert(EXTENSION_KEY.into(), metadata.projection());
    value.insert("ext".into(), V::Object(ext));
    let claim = CandidateClaim::from_value(&V::Object(value)).unwrap();
    assert!(service
        .recheck_classification_supports(&[claim])
        .await
        .is_err());
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn checkpoint_publication_boundaries_resume_from_frozen_evaluation() {
    for fail_at in [1, 2, 4] {
        eprintln!("checkpoint boundary {fail_at}: fixture");
        let fixture = AcquisitionV2Fixture::create().await.unwrap();
        let config = fixture.config().unwrap();
        let job = JobId::new(format!("job:checkpoint-failure:{fail_at}")).unwrap();
        let mut service = AcquisitionService::open(&config, fixture.catalog_identity().clone())
            .await
            .unwrap();
        let claim_id = freeze_draft(&service, &job).await;
        let writer = service.source_writer.clone();
        Arc::get_mut(&mut service).unwrap().source_writer = Arc::new(FailNthPut {
            inner: writer,
            calls: Arc::new(AtomicUsize::new(0)),
            fail_at,
        });
        eprintln!("checkpoint boundary {fail_at}: complete");
        let interrupted = service.complete_work(&job, WaitPoint::Admitted).await;
        eprintln!("checkpoint boundary {fail_at}: interrupted");
        if fail_at < 3 {
            assert!(interrupted.is_err());
            assert!(service.control.prepared_records().await.unwrap().is_empty());
        } else {
            let pending = interrupted.unwrap();
            assert!(pending.business.is_some());
            assert!(pending.publication_error.is_some());
            assert!(service.work.get(&job, "result").unwrap().is_some());
        }
        let review_before = service.control.review_prepared_records().await.unwrap();
        assert_eq!(review_before.len(), usize::from(fail_at > 1));
        service.shutdown().await.unwrap();
        drop(service);
        let reopened = AcquisitionService::open(&config, fixture.catalog_identity().clone())
            .await
            .unwrap();
        eprintln!("checkpoint boundary {fail_at}: reopened");
        let completed = reopened
            .complete_work(&job, WaitPoint::Admitted)
            .await
            .unwrap();
        assert_successor_result(
            &reopened,
            &job,
            &completed,
            "urn:ctxql:review:recovery",
            &claim_id,
        )
        .await;
        assert_eq!(fixture.pi_invocations().unwrap(), 0);
        assert_eq!(reopened.control.prepared_records().await.unwrap().len(), 1);
        assert_eq!(
            reopened
                .control
                .review_prepared_records()
                .await
                .unwrap()
                .len(),
            2
        );
        for original in review_before {
            let recovered = reopened
                .control
                .review_prepared(&original.bundle_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(recovered, original);
        }
        reopened.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn stale_absent_review_is_superseded_under_writer_session_without_duplicate_commit() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let config = fixture.config().unwrap();
    let job = JobId::new("job:stale-absent-review").unwrap();
    let service = AcquisitionService::open(&config, fixture.catalog_identity().clone())
        .await
        .unwrap();
    let claim_id = freeze_draft(&service, &job).await;
    let stale = seal_initial_review_attempt(&service, &job).await;

    commit_intervening_review(&service).await;
    let completed = service
        .complete_work(&job, WaitPoint::Admitted)
        .await
        .unwrap();
    assert_successor_result(
        &service,
        &job,
        &completed,
        "urn:ctxql:review:recovery",
        &claim_id,
    )
    .await;

    let supersessions = service.control.superseded_absent_records().await.unwrap();
    let superseded = supersessions
        .iter()
        .find(|record| record.predecessor_bundle_id == *stale.id())
        .expect("durable stale-absent proof");
    assert_eq!(superseded.kind, SupersededPreparedKind::Review);
    assert_eq!(superseded.predecessor_attempt_id, *stale.attempt_id());
    assert_ne!(superseded.successor_attempt_id, *stale.attempt_id());
    assert_ne!(superseded.successor_bundle_id, *stale.id());
    assert!(service
        .control
        .review_admission(stale.id())
        .await
        .unwrap()
        .is_none());
    let successor_receipt = service
        .control
        .review_admission(&superseded.successor_bundle_id)
        .await
        .unwrap()
        .expect("successor admission");
    let prepared_before = service.control.review_prepared_records().await.unwrap();
    let successor_prepared = prepared_before
        .iter()
        .find(|prepared| prepared.bundle_id == superseded.successor_bundle_id)
        .expect("successor prepared record");
    assert_eq!(
        successor_prepared.validation_capture,
        superseded.successor_capture
    );
    assert_ne!(successor_prepared.descriptor_root, *stale.descriptor_root());
    let supersessions_before = supersessions.clone();

    service.shutdown().await.unwrap();
    drop(service);
    let reopened = AcquisitionService::open(&config, fixture.catalog_identity().clone())
        .await
        .unwrap();
    let replayed = reopened
        .complete_work(&job, WaitPoint::Admitted)
        .await
        .unwrap();
    assert_eq!(
        replayed.review.projection(),
        successor_receipt.projection(),
        "replay must recover the admitted successor"
    );
    assert_eq!(
        reopened.control.review_prepared_records().await.unwrap(),
        prepared_before,
        "replay must not prepare or commit another successor"
    );
    assert_eq!(
        reopened.control.superseded_absent_records().await.unwrap(),
        supersessions_before
    );
    assert_eq!(fixture.pi_invocations().unwrap(), 0);
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn stale_absent_business_preserves_claim_identity_and_commits_only_successor() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let config = fixture.config().unwrap();
    let job = JobId::new("job:stale-absent-business").unwrap();
    let service = AcquisitionService::open(&config, fixture.catalog_identity().clone())
        .await
        .unwrap();
    let claim_id = freeze_draft(&service, &job).await;
    let stale = seal_initial_business_attempt(&service, &job).await;

    // Completing the review is the intervening writer transaction which makes
    // the immutable business checkpoint stale before its recovery begins.
    let completed = service
        .complete_work(&job, WaitPoint::Admitted)
        .await
        .unwrap();
    assert_eq!(
        completed.business.as_ref().unwrap().claim_ids(),
        &[claim_id]
    );
    let supersessions = service.control.superseded_absent_records().await.unwrap();
    let superseded = supersessions
        .iter()
        .find(|record| record.predecessor_bundle_id == *stale.id())
        .expect("durable business stale-absent proof");
    assert_eq!(superseded.kind, SupersededPreparedKind::Business);
    assert_eq!(
        superseded.predecessor_attempt_id,
        bundle_attempt_id(&stale).unwrap()
    );
    assert_ne!(
        superseded.successor_attempt_id,
        superseded.predecessor_attempt_id
    );
    assert!(service
        .control
        .admission(stale.id())
        .await
        .unwrap()
        .is_none());
    let successor_receipt = service
        .control
        .admission(&superseded.successor_bundle_id)
        .await
        .unwrap()
        .expect("business successor admission");
    assert_eq!(successor_receipt.claim_ids(), stale.expected_claim_ids());
    let prepared_before = service.control.prepared_records().await.unwrap();
    let successor_prepared = prepared_before
        .iter()
        .find(|prepared| prepared.bundle_id == superseded.successor_bundle_id)
        .expect("business successor prepared record");
    assert_eq!(
        successor_prepared.validation_capture,
        superseded.successor_capture
    );
    assert_ne!(successor_prepared.descriptor_root, *stale.descriptor_root());

    service.shutdown().await.unwrap();
    drop(service);
    let service = AcquisitionService::open(&config, fixture.catalog_identity().clone())
        .await
        .unwrap();
    let replayed = service
        .complete_work(&job, WaitPoint::Admitted)
        .await
        .unwrap();
    assert_eq!(
        replayed.business.as_ref().unwrap().projection(),
        successor_receipt.projection()
    );
    assert_eq!(
        service.control.prepared_records().await.unwrap(),
        prepared_before,
        "replay must not create a duplicate business commit"
    );
    assert_eq!(fixture.pi_invocations().unwrap(), 0);
    service.shutdown().await.unwrap();
}

async fn freeze_large_artifact(
    service: &AcquisitionService,
    job: &JobId,
    bytes: &[u8],
) -> AcquisitionArtifactDescriptor {
    let root = service
        .source_writer
        .put(bytes, service.artifact_limit)
        .await
        .unwrap();
    let descriptor = AcquisitionArtifactDescriptor::new(
        SourceReadRequest {
            source_id: SourceId::new(format!("urn:source:{}", job.as_str())).unwrap(),
            version: ContentHash::of_bytes(format!("version:{}", job.as_str()).as_bytes()),
            selector: EvidenceSelector::WholeDocument,
            max_bytes: service.artifact_limit,
        },
        ContentHash::of_bytes(format!("fragment:{}", job.as_str()).as_bytes()),
        root,
        "provider_raw_response",
        ContentHash::of_bytes(format!("context:{}", job.as_str()).as_bytes()),
    )
    .unwrap();
    freeze_draft_with_report(
        service,
        job,
        V::object([(
            "artifact_descriptors".into(),
            V::Array(vec![descriptor.projection()]),
        )])
        .unwrap(),
    )
    .await;
    descriptor
}

#[tokio::test]
async fn large_artifact_pages_and_index_are_bounded_and_source_bound() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let mut config = fixture.config().unwrap();
    config.limits.run_bytes = 64 * 1024;
    let service = AcquisitionService::open(&config, fixture.catalog_identity().clone())
        .await
        .unwrap();
    let job = JobId::new("job:bounded-artifact-pages").unwrap();
    assert_eq!(service.artifact_page_limit, config.limits.run_bytes);
    let bytes = vec![b'x'; config.limits.run_bytes + 31_337];
    let authority = freeze_large_artifact(&service, &job, &bytes).await;

    let completed = service
        .complete_work(&job, WaitPoint::Admitted)
        .await
        .unwrap();
    assert!(completed.publication_error.is_none());
    assert!(service.work.get(&job, "artifact_pages").unwrap().is_some());
    let descriptors = service.artifact_page_descriptors(&job).await.unwrap();
    assert_eq!(descriptors.len(), 3, "two pages and one index");
    for descriptor in &descriptors {
        assert_eq!(descriptor.source(), authority.source());
        assert_eq!(descriptor.context_root(), authority.context_root());
        assert_eq!(
            descriptor.source_fragment_hash(),
            authority.source_fragment_hash()
        );
        let object = service
            .source_reader
            .read(descriptor.artifact_root(), service.artifact_limit)
            .await
            .unwrap();
        assert!(object.bytes().len() <= artifact_page_cap(service.artifact_page_limit));
    }
    let index = descriptors
        .iter()
        .find(|descriptor| {
            descriptor
                .projection()
                .field("artifact_kind")
                .unwrap()
                .as_str()
                .unwrap()
                == "artifact_page_index"
        })
        .unwrap();
    let index = service
        .read_work_object(index.artifact_root())
        .await
        .unwrap();
    let mut reconstructed = Vec::new();
    for page in index.field("pages").unwrap().as_array().unwrap() {
        let root = ContentHash::parse(page.field("root").unwrap().as_str().unwrap()).unwrap();
        reconstructed.extend_from_slice(
            service
                .source_reader
                .read(&root, service.artifact_limit)
                .await
                .unwrap()
                .bytes(),
        );
    }
    assert_eq!(reconstructed, bytes);
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn artifact_page_index_publication_failure_resumes_idempotently() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let config = fixture.config().unwrap();
    let job = JobId::new("job:artifact-page-index-recovery").unwrap();
    let mut service = AcquisitionService::open(&config, fixture.catalog_identity().clone())
        .await
        .unwrap();
    let bytes = vec![b'y'; ARTIFACT_PAGE_TARGET_BYTES + 17];
    freeze_large_artifact(&service, &job, &bytes).await;
    let writer = service.source_writer.clone();
    Arc::get_mut(&mut service).unwrap().source_writer = Arc::new(FailNthPut {
        inner: writer,
        calls: Arc::new(AtomicUsize::new(0)),
        // review, business, result, two pages, then their index
        fail_at: 6,
    });
    let pending = service
        .complete_work(&job, WaitPoint::Admitted)
        .await
        .unwrap();
    let business = pending.business.as_ref().unwrap().projection();
    assert_eq!(pending.publication_error, Some("preparation_failed"));
    assert!(pending.result_root.is_none());
    assert!(service.work.get(&job, "result").unwrap().is_some());
    assert!(service.work.get(&job, "artifact_pages").unwrap().is_none());

    service.shutdown().await.unwrap();
    drop(service);
    let reopened = AcquisitionService::open(&config, fixture.catalog_identity().clone())
        .await
        .unwrap();
    let recovered = reopened
        .complete_work(&job, WaitPoint::Admitted)
        .await
        .unwrap();
    assert!(recovered.publication_error.is_none());
    assert_eq!(recovered.business.as_ref().unwrap().projection(), business);
    assert_eq!(
        reopened
            .artifact_page_descriptors(&job)
            .await
            .unwrap()
            .len(),
        3
    );
    assert_eq!(fixture.pi_invocations().unwrap(), 0);
    assert_eq!(
        reopened
            .control
            .prepared_records()
            .await
            .unwrap()
            .iter()
            .filter(|prepared| prepared.job_id == job)
            .count(),
        1
    );
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn result_publication_failure_recovers_without_reinvocation_or_business_recommit() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let config = fixture.config().unwrap();
    let job = JobId::new("job:work-result-publication-recovery").unwrap();
    let mut service = AcquisitionService::open(&config, fixture.catalog_identity().clone())
        .await
        .unwrap();
    let claim_id = freeze_draft(&service, &job).await;

    let real_writer = service.source_writer.clone();
    let put_calls = Arc::new(AtomicUsize::new(0));
    Arc::get_mut(&mut service).unwrap().source_writer = Arc::new(FailNthPut {
        inner: real_writer,
        calls: put_calls.clone(),
        // review checkpoint, business checkpoint, then result artifact publication
        fail_at: 3,
    });
    let pending = service
        .complete_work(&job, WaitPoint::Admitted)
        .await
        .unwrap();

    let committed = pending
        .business
        .as_ref()
        .expect("business receipt survives publication failure")
        .projection();
    assert_eq!(put_calls.load(Ordering::SeqCst), 3);
    assert_eq!(pending.publication_error, Some("preparation_failed"));
    assert!(pending.result_root.is_none());
    assert!(pending.result_review.is_none());
    assert_eq!(
        pending.business.as_ref().unwrap().claim_ids(),
        std::slice::from_ref(&claim_id)
    );
    assert!(service.work.get(&job, "result").unwrap().is_none());
    assert_eq!(fixture.pi_invocations().unwrap(), 0);

    service.shutdown().await.unwrap();
    drop(service);
    let reopened = AcquisitionService::open(&config, fixture.catalog_identity().clone())
        .await
        .unwrap();
    let recovered = reopened
        .complete_work(&job, WaitPoint::Admitted)
        .await
        .unwrap();

    assert_eq!(recovered.business.as_ref().unwrap().projection(), committed);
    assert_successor_result(
        &reopened,
        &job,
        &recovered,
        "urn:ctxql:review:recovery",
        &claim_id,
    )
    .await;
    assert_eq!(fixture.pi_invocations().unwrap(), 0);
    assert_eq!(
        reopened
            .control
            .prepared_records()
            .await
            .unwrap()
            .iter()
            .filter(|prepared| prepared.job_id == job)
            .count(),
        1,
        "publication recovery must not create a duplicate business transaction"
    );
    reopened.shutdown().await.unwrap();
}
