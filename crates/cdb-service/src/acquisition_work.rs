//! Resumable v2 evaluation -> review -> business -> receipt-linked result.
//! Frozen content lives in evidence storage; Control contains only immutable links.

use crate::{
    acquisition::{AcquisitionService, WaitPoint},
    graph_capture::{GraphCaptureIndex, GraphCaptureLimits},
    graph_query::GraphQueryHost,
    graph_session::GraphSession,
    sources::{
        acquisition_selector_records, selector_records, AcquisitionArtifactDescriptor,
        SourcePlusGraphArtifactDescriptor,
    },
};
use cdb_backend_fluree::acquisition_writer::FlureeWriterSession;
use cdb_core::{
    acquisition::{
        AdmissionRecovery, BundlePrepared, PreparedSupersededAbsent, ReviewAdmissionRecovery,
        SupersededPreparedKind,
    },
    admission::{AdmissionBatch, ExportRecord, ResourceChange},
    claim::CandidateClaim,
    contracts::GraphBackend,
    id::{AttemptId, BackendId, BundleId, ContentHash, ExtractionRunId, IdempotencyKey, JobId},
    review::{
        ReviewAdmissionReceipt, ReviewBundlePrepared, ReviewRecord, ReviewRecordId,
        ValidatedReviewBundle,
    },
    semantic_admission::{SemanticAdmissionReceipt, ValidatedSemanticBundle},
    snapshot::{GraphPin, SnapshotRef},
    CanonicalValue as V, Error, ErrorKind, Limits, Result, Timestamp,
};
use std::{
    collections::BTreeSet,
    sync::{atomic::AtomicBool, Arc},
    time::Instant,
};

pub(crate) struct WorkOutcome {
    pub review: ReviewAdmissionReceipt,
    pub business: Option<SemanticAdmissionReceipt>,
    business_bundle_id: Option<BundleId>,
    pub result_root: Option<ContentHash>,
    pub result_review: Option<ReviewAdmissionReceipt>,
    pub publication_error: Option<&'static str>,
    pub projection_error: Option<&'static str>,
}

impl AcquisitionService {
    pub(crate) async fn read_work_object(&self, root: &ContentHash) -> Result<V> {
        let object = self.source_reader.read(root, self.artifact_limit).await?;
        V::parse(object.bytes(), Limits::default())
    }

    pub(crate) async fn work_value(&self, job: &JobId, stage: &str) -> Result<Option<V>> {
        match self.work.get(job, stage)? {
            Some(root) => Ok(Some(self.read_work_object(&root).await?)),
            None => Ok(None),
        }
    }

    pub(crate) async fn seal_work_value(
        &self,
        job: &JobId,
        stage: &str,
        value: &V,
    ) -> Result<ContentHash> {
        let bytes = value.canonical_bytes(Limits::default())?;
        let root = self.source_writer.put(&bytes, self.artifact_limit).await?;
        self.work.put(job, stage, &root)?;
        Ok(root)
    }

    pub(crate) async fn complete_work_guarded(
        self: &Arc<Self>,
        job: &JobId,
        wait: WaitPoint,
        graph: Option<Arc<GraphSession>>,
    ) -> Result<WorkOutcome> {
        let Some(graph) = graph else {
            return self.complete_work(job, wait).await;
        };
        graph.authorize_final_release().await?;
        self.provision_frozen_work_selectors(job).await?;
        let service = self.clone();
        let job = job.clone();
        let query = graph.query_host();
        let outcome = graph
            .guarded_final_action(move |dependencies| async move {
                service
                    .complete_work_inner(&job, wait, Some((query, dependencies)))
                    .await
            })
            .await?;
        graph.complete()?;
        Ok(outcome)
    }

    pub(crate) async fn complete_work_guarded_dependencies(
        self: &Arc<Self>,
        job: &JobId,
        wait: WaitPoint,
        query: Arc<GraphQueryHost>,
        dependencies: BTreeSet<String>,
        deadline: Instant,
    ) -> Result<WorkOutcome> {
        query
            .guarded_disclosure_action(
                dependencies.clone(),
                Arc::new(AtomicBool::new(false)),
                deadline,
                || async { Ok(()) },
            )
            .await?;
        self.provision_frozen_work_selectors(job).await?;
        let service = self.clone();
        let job = job.clone();
        let guarded_query = query.clone();
        query
            .guarded_control_action(
                Arc::new(AtomicBool::new(false)),
                deadline,
                move || async move {
                    service
                        .complete_work_inner(&job, wait, Some((guarded_query, dependencies)))
                        .await
                },
            )
            .await
    }

    pub(crate) async fn complete_work(&self, job: &JobId, wait: WaitPoint) -> Result<WorkOutcome> {
        self.complete_work_inner(job, wait, None).await
    }

    async fn complete_work_inner(
        &self,
        job: &JobId,
        wait: WaitPoint,
        graph_authority: Option<(Arc<GraphQueryHost>, BTreeSet<String>)>,
    ) -> Result<WorkOutcome> {
        let draft = self
            .work_value(job, "evaluation")
            .await?
            .ok_or_else(|| Error::invalid("missing frozen acquisition evaluation"))?;
        let graph_work = match draft.field("schema")?.as_str()? {
            "ctxql-acquisition-work/v1" => {
                draft.closed(
                    &[
                        "schema",
                        "job_id",
                        "review",
                        "claims",
                        "assertions",
                        "ontology_mode",
                        "extraction_run",
                        "report",
                    ],
                    &[],
                )?;
                false
            }
            "ctxql-acquisition-graph-work/v1" => {
                draft.closed(
                    &[
                        "schema",
                        "job_id",
                        "review",
                        "claims",
                        "assertions",
                        "ontology_mode",
                        "extraction_run",
                        "report",
                        "graph",
                        "graph_artifact_descriptors",
                    ],
                    &[],
                )?;
                true
            }
            _ => return Err(Error::invalid("acquisition work schema")),
        };
        if draft.field("job_id")?.as_str()? != job.as_str() {
            return Err(Error::invalid("acquisition work binding"));
        }
        if graph_work && graph_authority.is_none() {
            return Err(Error::new(
                ErrorKind::Denied,
                "graph acquisition requires current guarded session",
            ));
        }
        if graph_work {
            let frozen_dependencies = self.frozen_graph_dependencies(job, &draft).await?;
            let capability_root =
                ContentHash::parse(draft.field("graph")?.field("capability_root")?.as_str()?)?;
            let capability = self.read_work_object(&capability_root).await?;
            graph_authority
                .as_ref()
                .expect("graph authority checked above")
                .0
                .require_capture_binding(&capability)?;
            let supplied_dependencies = &graph_authority
                .as_ref()
                .expect("graph authority checked above")
                .1;
            if supplied_dependencies != &frozen_dependencies {
                return Err(Error::new(
                    ErrorKind::Denied,
                    "graph acquisition dependency binding mismatch",
                ));
            }
        }
        let frozen_review =
            ValidatedReviewBundle::from_value(draft.field("review")?, Limits::default())?;
        let claims = draft
            .field("claims")?
            .as_array()?
            .iter()
            .map(CandidateClaim::from_value)
            .collect::<Result<Vec<_>>>()?;
        let artifact_descriptors = acquisition_artifact_descriptors(&draft, self.artifact_limit)?;
        let graph_artifact_descriptors = if graph_work {
            graph_artifact_descriptors(&draft, self.artifact_limit)?
        } else {
            Vec::new()
        };
        // Graph callers provision before acquiring the Control mutation gate;
        // selector admission itself acquires that gate. Exact dependencies are
        // checked again below under the Semantic writer session.
        if graph_authority.is_none() {
            self.provision_acquisition_selectors(
                &claims,
                &artifact_descriptors,
                &graph_artifact_descriptors,
            )
            .await?;
        }
        let session = self.semantic_writer.session().await;
        if let Some((query, dependencies)) = &graph_authority {
            query
                .authorize_writer_session(&session, dependencies)
                .await?;
        }
        let review_bundle = match self.work_value(job, "review").await? {
            Some(value) => ValidatedReviewBundle::from_value(&value, Limits::default())?,
            None => {
                // Eligibility is not admission. Initial review records have no accepted links.
                let records = frozen_review
                    .records()
                    .iter()
                    .map(|record| {
                        let mut value = record.projection();
                        if let V::Object(fields) = &mut value {
                            fields.insert("accepted_claim_ids".into(), V::Array(vec![]));
                        }
                        ReviewRecord::from_value(&value)
                    })
                    .collect::<Result<Vec<_>>>()?;
                let bundle = ValidatedReviewBundle::new(
                    frozen_review.id().clone(),
                    frozen_review.evaluation_id(),
                    frozen_review.logical_bundle_key(),
                    frozen_review.attempt_id().clone(),
                    session.capture_current().await?,
                    records,
                    Limits::default(),
                )?;
                self.seal_work_value(job, "review", &bundle.projection())
                    .await?;
                bundle
            }
        };
        let review = self
            .commit_work_review(job, &session, &review_bundle)
            .await?;
        let business = if draft.field("assertions")?.as_str()? == "accepted" && !claims.is_empty() {
            let bundle = match self.work_value(job, "business").await? {
                Some(value) => decode_business(&value)?,
                None => {
                    self.recheck_classification_supports(&claims).await?;
                    let capture = session.capture_current().await?;
                    let descriptor = V::object([
                        (
                            "schema".into(),
                            V::string("ctxql-extraction-admission-descriptor/v2"),
                        ),
                        (
                            "evaluation_id".into(),
                            V::string(frozen_review.evaluation_id()),
                        ),
                        (
                            "review_payload_root".into(),
                            V::string(review.payload_root().as_str()),
                        ),
                        (
                            "ontology_mode".into(),
                            draft.field("ontology_mode")?.clone(),
                        ),
                    ])?;
                    let key = ContentHash::of_bytes(
                        &V::Array(vec![V::string(job.as_str()), capture.projection()])
                            .canonical_bytes(Limits::default())?,
                    );
                    let bundle = ValidatedSemanticBundle::new(
                        BundleId::new(format!("bundle:{}", &key.as_str()[7..]))?,
                        ExtractionRunId::new(draft.field("extraction_run")?.as_str()?)?,
                        capture,
                        descriptor,
                        claims
                            .iter()
                            .cloned()
                            .map(|claim| {
                                (
                                    format!(
                                        "v2:{}",
                                        claim.id().as_str().rsplit(':').next().unwrap()
                                    ),
                                    claim,
                                )
                            })
                            .collect(),
                        Limits::default(),
                    )?;
                    self.seal_work_value(
                        job,
                        "business",
                        &V::object([
                            (
                                "backend".into(),
                                V::string(bundle.validation_capture().backend().as_str()),
                            ),
                            ("bundle".into(), bundle.projection()),
                        ])?,
                    )
                    .await?;
                    bundle
                }
            };
            let source_selector_root = self
                .work
                .get(job, "evaluation")?
                .ok_or_else(|| Error::invalid("missing evaluation checkpoint"))?;
            Some(
                self.commit_work_business(
                    job,
                    &session,
                    bundle,
                    source_selector_root,
                    claims.len(),
                    graph_authority.as_ref(),
                )
                .await?,
            )
        } else {
            None
        };
        let mut outcome = WorkOutcome {
            review,
            business_bundle_id: business.as_ref().map(|(_, bundle)| bundle.clone()),
            business: business.map(|(receipt, _)| receipt),
            result_root: None,
            result_review: None,
            publication_error: None,
            projection_error: None,
        };
        // After admission, publication failures are pending work, never a false non-admission.
        match self
            .publish_work_result(job, &session, &frozen_review, &outcome)
            .await
        {
            Ok((root, receipt)) => {
                outcome.result_root = Some(root);
                outcome.result_review = Some(receipt);
            }
            Err(error) => outcome.publication_error = Some(error.public_code()),
        }
        drop(session);
        if wait == WaitPoint::Projected {
            if let Some(receipt) = &outcome.business {
                match self.projection.wait_exact(receipt).await {
                    Ok(projection) => {
                        let bundle = outcome
                            .business_bundle_id
                            .as_ref()
                            .ok_or_else(|| Error::invalid("missing admitted business bundle"))?;
                        if let Err(error) =
                            self.control.append_projection(bundle, &projection).await
                        {
                            outcome.projection_error = Some(error.public_code());
                        }
                    }
                    Err(error) => outcome.projection_error = Some(error.public_code()),
                }
            }
        }
        Ok(outcome)
    }

    /// Recover the exact disclosed dependency set from the immutable capture
    /// index registered by the frozen graph work image. The caller's replay or
    /// live-session set is only authority input; it may not narrow or widen the
    /// dependencies retained with the work across process reopen.
    pub(crate) async fn frozen_graph_dependencies(
        &self,
        job: &JobId,
        draft: &V,
    ) -> Result<BTreeSet<String>> {
        let graph = draft.field("graph")?;
        let registered = |stage: &str, field: &str| -> Result<ContentHash> {
            let root = ContentHash::parse(graph.field(field)?.as_str()?)?;
            if self.work.get(job, stage)?.as_ref() != Some(&root) {
                return Err(Error::invalid("graph acquisition registered root"));
            }
            Ok(root)
        };
        let capture_root = registered("graph_capture", "capture_root")?;
        let context_root = registered("graph_context", "context_root")?;
        let workspace_root = registered("graph_workspace", "workspace_root")?;
        let capability_root = registered("graph_capability", "capability_root")?;
        let index_value = self.read_work_object(&capture_root).await?;
        let index = GraphCaptureIndex::from_value(&index_value, GraphCaptureLimits::default())?;
        if index.root()? != capture_root
            || index_value.field("graph_context_root")?.as_str()? != context_root.as_str()
            || index_value.field("final_workspace_root")?.as_str()? != workspace_root.as_str()
            || index_value.field("capability_summary_root")?.as_str()? != capability_root.as_str()
            || index_value.field("leaf_roots")? != graph.field("leaf_roots")?
        {
            return Err(Error::invalid("graph acquisition capture binding"));
        }
        index_value
            .field("claim_dependencies")?
            .as_array()?
            .iter()
            .map(|value| {
                let dependency = value.as_str()?.to_owned();
                cdb_core::id::ResourceId::new(&dependency)?;
                Ok(dependency)
            })
            .collect()
    }

    async fn provision_frozen_work_selectors(&self, job: &JobId) -> Result<()> {
        let draft = self
            .work_value(job, "evaluation")
            .await?
            .ok_or_else(|| Error::invalid("missing frozen acquisition evaluation"))?;
        if draft.field("job_id")?.as_str()? != job.as_str()
            || draft.field("schema")?.as_str()? != "ctxql-acquisition-graph-work/v1"
        {
            return Err(Error::invalid("graph acquisition work binding"));
        }
        let claims = draft
            .field("claims")?
            .as_array()?
            .iter()
            .map(CandidateClaim::from_value)
            .collect::<Result<Vec<_>>>()?;
        let artifacts = acquisition_artifact_descriptors(&draft, self.artifact_limit)?;
        let graph_artifacts = graph_artifact_descriptors(&draft, self.artifact_limit)?;
        self.provision_acquisition_selectors(&claims, &artifacts, &graph_artifacts)
            .await
    }

    /// Provision selector records derived from validated claim lineage and
    /// frozen host-produced artifact descriptors. Caller/model supplied
    /// descriptor objects never enter this path.
    async fn provision_acquisition_selectors(
        &self,
        claims: &[CandidateClaim],
        artifacts: &[AcquisitionArtifactDescriptor],
        graph_artifacts: &[SourcePlusGraphArtifactDescriptor],
    ) -> Result<()> {
        let mut desired = std::collections::BTreeMap::new();
        {
            let mut insert = |record: ExportRecord| -> Result<()> {
                let ExportRecord::Resource(record) = record else {
                    return Err(Error::invalid("acquisition selector record"));
                };
                match desired.entry(record.id().as_str().to_owned()) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(record);
                    }
                    std::collections::btree_map::Entry::Occupied(entry)
                        if entry.get() != &record =>
                    {
                        return Err(Error::new(
                            ErrorKind::Conflict,
                            "acquisition selector descriptor conflict",
                        ));
                    }
                    _ => {}
                }
                Ok(())
            };
            for source in claims.iter().flat_map(|claim| claim.lineage().sources()) {
                for record in acquisition_selector_records(source, self.artifact_limit)? {
                    insert(record)?;
                }
            }
            // Review-only/evidence-only work still needs source authorization.
            // These descriptors came from the frozen host-produced work image;
            // caller-supplied descriptors never reach this provisioning path.
            for artifact in artifacts {
                for record in selector_records(artifact.source(), artifact.source_fragment_hash())?
                {
                    insert(record)?;
                }
            }
            for artifact in graph_artifacts {
                for record in selector_records(artifact.source(), artifact.source_fragment_hash())?
                {
                    insert(record)?;
                }
            }
        }
        if desired.is_empty() {
            return Ok(());
        }
        let identity = V::Array(desired.values().map(|record| record.projection()).collect());
        let key_hash = ContentHash::of_bytes(&identity.canonical_bytes(Limits::default())?);
        let key =
            IdempotencyKey::new(format!("acquisition-selectors:{}", &key_hash.as_str()[7..]))?;
        if GraphBackend::receipt(self.authority.as_ref(), &key)
            .await?
            .is_some()
        {
            return Ok(());
        }
        let head = GraphBackend::head(self.authority.as_ref()).await?;
        let snapshot = self.authority.open_snapshot(&head).await?;
        let mut missing = Vec::new();
        for record in desired.into_values() {
            match snapshot.resource(record.id()).await? {
                Some(existing) if existing == record => {}
                Some(_) => {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "acquisition selector descriptor conflict",
                    ))
                }
                None => missing.push(ResourceChange::Add(record)),
            }
        }
        if missing.is_empty() {
            return Ok(());
        }
        let batch = AdmissionBatch::new(
            vec![],
            vec![],
            missing,
            vec![],
            V::object([
                (
                    "schema".into(),
                    V::string("ctxql-acquisition-selector-provision/v1"),
                ),
                ("set_root".into(), V::string(key_hash.as_str())),
            ])?,
            Limits::default(),
        )?;
        GraphBackend::admit(self.authority.as_ref(), &key, &batch).await?;
        Ok(())
    }

    async fn commit_work_review(
        &self,
        job: &JobId,
        session: &FlureeWriterSession<'_>,
        bundle: &ValidatedReviewBundle,
    ) -> Result<ReviewAdmissionReceipt> {
        let mut bundle = bundle.clone();
        for _ in 0..8 {
            let recorded_at = match self.control.review_prepared(bundle.id()).await? {
                Some(previous) => previous.recorded_at,
                None => work_timestamp()?,
            };
            let prepared = ReviewBundlePrepared::new(job.clone(), &bundle, recorded_at);
            self.control.append_review_prepared(&prepared).await?;
            if let Some(receipt) = self.control.review_admission(bundle.id()).await? {
                receipt.verify_prepared(&prepared)?;
                return Ok(receipt);
            }
            if let Some(record) = self.control.superseded_absent(bundle.id()).await? {
                verify_review_supersession(job, &bundle, &record)?;
                bundle = review_successor(&bundle, record.successor_capture.clone())?;
                continue;
            }
            match session.recover_review(&prepared).await? {
                ReviewAdmissionRecovery::Exact(receipt) => {
                    let receipt = *receipt;
                    self.control
                        .append_review_admission(bundle.id(), &receipt)
                        .await?;
                    return Ok(receipt);
                }
                ReviewAdmissionRecovery::Conflict => {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "review admission recovery conflict",
                    ))
                }
                ReviewAdmissionRecovery::Absent => {}
            }
            let capture = session.capture_current().await?;
            if capture == *bundle.validation_capture() {
                let receipt = session.recover_or_admit_review(&prepared, &bundle).await?;
                self.control
                    .append_review_admission(bundle.id(), &receipt)
                    .await?;
                return Ok(receipt);
            }
            let successor = review_successor(&bundle, capture.clone())?;
            let record = superseded_record(
                job,
                SupersededPreparedKind::Review,
                bundle.id(),
                bundle.attempt_id(),
                successor.id(),
                successor.attempt_id(),
                capture,
            )?;
            self.control.append_superseded_absent(&record).await?;
            bundle = successor;
        }
        Err(Error::limit())
    }

    async fn commit_work_business(
        &self,
        job: &JobId,
        session: &FlureeWriterSession<'_>,
        mut bundle: ValidatedSemanticBundle,
        source_selector_root: ContentHash,
        claim_count: usize,
        graph_authority: Option<&(Arc<GraphQueryHost>, BTreeSet<String>)>,
    ) -> Result<(SemanticAdmissionReceipt, BundleId)> {
        for _ in 0..8 {
            if let Some((query, dependencies)) = graph_authority {
                query
                    .authorize_writer_session(session, dependencies)
                    .await?;
            }
            let recorded_at = match self.control.prepared(bundle.id()).await? {
                Some(previous) => previous.recorded_at,
                None => work_timestamp()?,
            };
            let prepared = BundlePrepared {
                job_id: job.clone(),
                attempt_id: bundle_attempt_id(&bundle)?,
                bundle_id: bundle.id().clone(),
                admission_key: bundle.admission_key().as_str().to_owned(),
                descriptor_root: bundle.descriptor_root().clone(),
                payload_root: bundle.payload_root().clone(),
                canonical_claim_root: bundle.canonical_claim_root().clone(),
                expected_claim_ids: bundle.expected_claim_ids(),
                validation_capture: bundle.validation_capture().clone(),
                source_selector_root: source_selector_root.clone(),
                safe_counts: V::object([("claims".into(), V::integer(claim_count as u64))])?,
                recorded_at,
            };
            self.control.append_prepared(&prepared).await?;
            if let Some(receipt) = self.control.admission(bundle.id()).await? {
                verify_business_receipt(&prepared, &receipt)?;
                return Ok((receipt, bundle.id().clone()));
            }
            if let Some(record) = self.control.superseded_absent(bundle.id()).await? {
                verify_business_supersession(job, &prepared, &bundle, &record)?;
                bundle = business_successor(&bundle, record.successor_capture.clone())?;
                continue;
            }
            match session.recover_business(&prepared).await? {
                AdmissionRecovery::Exact(receipt) => {
                    let receipt = *receipt;
                    self.control.append_admission(bundle.id(), &receipt).await?;
                    return Ok((receipt, bundle.id().clone()));
                }
                AdmissionRecovery::Conflict => {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "semantic admission recovery conflict",
                    ))
                }
                AdmissionRecovery::Absent => {}
            }
            self.recheck_classification_supports(bundle.claims())
                .await?;
            let capture = session.capture_current().await?;
            if capture == *bundle.validation_capture() {
                let receipt = if let Some((query, dependencies)) = graph_authority {
                    session
                        .recover_or_admit_business_with_disclosure(
                            query.semantic_principal(),
                            query.semantic_action(),
                            query.policy_basis(),
                            dependencies,
                            &prepared,
                            &bundle,
                        )
                        .await?
                } else {
                    session
                        .recover_or_admit_business(&prepared, &bundle)
                        .await?
                };
                self.control.append_admission(bundle.id(), &receipt).await?;
                return Ok((receipt, bundle.id().clone()));
            }
            let successor = business_successor(&bundle, capture.clone())?;
            let record = superseded_record(
                job,
                SupersededPreparedKind::Business,
                bundle.id(),
                &prepared.attempt_id,
                successor.id(),
                &bundle_attempt_id(&successor)?,
                capture,
            )?;
            self.control.append_superseded_absent(&record).await?;
            bundle = successor;
        }
        Err(Error::limit())
    }

    async fn publish_work_result(
        &self,
        job: &JobId,
        session: &FlureeWriterSession<'_>,
        frozen: &ValidatedReviewBundle,
        outcome: &WorkOutcome,
    ) -> Result<(ContentHash, ReviewAdmissionReceipt)> {
        let accepted = outcome
            .business
            .as_ref()
            .map(|r| r.claim_ids().to_vec())
            .unwrap_or_default();
        let result = V::object([
            (
                "schema".into(),
                V::string("ctxql-extraction-admission-result/v2"),
            ),
            ("job_id".into(), V::string(job.as_str())),
            ("evaluation_id".into(), V::string(frozen.evaluation_id())),
            ("review_receipt".into(), outcome.review.projection()),
            (
                "business_receipt".into(),
                outcome
                    .business
                    .as_ref()
                    .map(|r| r.projection())
                    .unwrap_or(V::Null),
            ),
            (
                "accepted_claim_ids".into(),
                V::Array(accepted.iter().map(|id| V::string(id.as_str())).collect()),
            ),
            (
                "supersedes_review_ids".into(),
                V::Array(
                    frozen
                        .records()
                        .iter()
                        .map(|r| V::string(r.id().as_str()))
                        .collect(),
                ),
            ),
        ])?;
        let root = self.seal_work_value(job, "result", &result).await?;
        let draft = self
            .work_value(job, "evaluation")
            .await?
            .ok_or_else(|| Error::invalid("missing frozen acquisition evaluation"))?;
        if draft.field("schema")?.as_str()? == "ctxql-acquisition-graph-work/v1" {
            let artifacts = graph_artifact_descriptors(&draft, self.artifact_limit)?;
            self.persist_graph_artifact_pages(job, &draft, &artifacts, &root)
                .await?;
        } else {
            let artifacts = acquisition_artifact_descriptors(&draft, self.artifact_limit)?;
            self.persist_artifact_pages(job, &artifacts, &root).await?;
        }
        let bundle = match self.work_value(job, "result_review").await? {
            Some(value) => ValidatedReviewBundle::from_value(&value, Limits::default())?,
            None => {
                let mut records = Vec::new();
                for record in frozen.records() {
                    let ids = record
                        .accepted_claim_ids()
                        .iter()
                        .filter(|id| accepted.contains(id))
                        .cloned()
                        .collect::<Vec<_>>();
                    let key = ContentHash::of_bytes(
                        format!(
                            "ctxql-review-result/v1\0{}\0{}",
                            root.as_str(),
                            record.id().as_str()
                        )
                        .as_bytes(),
                    );
                    records.push(ReviewRecord::new(
                        ReviewRecordId::new(format!(
                            "urn:ctxql:review:result:{}",
                            &key.as_str()[7..]
                        ))?,
                        record.component_ref(),
                        record.source_ref(),
                        root.clone(),
                        record.vocabulary_verdict(),
                        record.assertion_intent(),
                        vec![if ids.is_empty() {
                            "evidence_only"
                        } else {
                            "business_admitted"
                        }
                        .into()],
                        record.suggested_predicates().to_vec(),
                        record.suggested_types().to_vec(),
                        record.resolved_predicates().to_vec(),
                        record.resolved_types().to_vec(),
                        ids,
                    )?);
                }
                let bundle = ValidatedReviewBundle::new(
                    BundleId::new(format!("bundle:result:{}", &root.as_str()[7..]))?,
                    frozen.evaluation_id(),
                    format!("{}:result", frozen.logical_bundle_key()),
                    AttemptId::new(format!("attempt:result:{}", &root.as_str()[7..]))?,
                    session.capture_current().await?,
                    records,
                    Limits::default(),
                )?;
                self.seal_work_value(job, "result_review", &bundle.projection())
                    .await?;
                bundle
            }
        };
        let receipt = self.commit_work_review(job, session, &bundle).await?;
        Ok((root, receipt))
    }

    /// Return only page/index descriptors authenticated by the immutable
    /// evaluation and artifact-pages work links. Inspection may append these
    /// to its already-authorized descriptor set; this function never writes.
    pub(crate) async fn artifact_page_descriptors(
        &self,
        job: &JobId,
    ) -> Result<Vec<AcquisitionArtifactDescriptor>> {
        let Some(catalog_root) = self.work.get(job, "artifact_pages")? else {
            return Ok(Vec::new());
        };
        let draft = self
            .work_value(job, "evaluation")
            .await?
            .ok_or_else(|| Error::invalid("missing frozen acquisition evaluation"))?;
        if draft.field("job_id")?.as_str()? != job.as_str() {
            return Err(Error::invalid("acquisition work binding"));
        }
        let originals = acquisition_artifact_descriptors(&draft, self.artifact_limit)?;
        let catalog = self.read_work_object(&catalog_root).await?;
        catalog.closed(&["schema", "job_id", "entries"], &[])?;
        if catalog.field("schema")?.as_str()? != "ctxql-acquisition-artifact-pages/v1"
            || catalog.field("job_id")?.as_str()? != job.as_str()
        {
            return Err(Error::invalid("artifact page catalog binding"));
        }
        let page_cap = artifact_page_cap(self.artifact_page_limit);
        let mut output = Vec::new();
        for entry in catalog.field("entries")?.as_array()? {
            entry.closed(&["authority", "artifact", "index"], &[])?;
            let authority = AcquisitionArtifactDescriptor::from_value(
                entry.field("authority")?,
                self.artifact_limit,
            )?;
            if !originals.contains(&authority) {
                return Err(Error::invalid("artifact page authority"));
            }
            let artifact = AcquisitionArtifactDescriptor::from_value(
                entry.field("artifact")?,
                self.artifact_limit,
            )?;
            validate_paged_artifact_binding(self, job, &authority, &artifact)?;
            let index = AcquisitionArtifactDescriptor::from_value(
                entry.field("index")?,
                self.artifact_limit,
            )?;
            if index != artifact.successor(index.artifact_root().clone(), "artifact_page_index")? {
                return Err(Error::invalid("artifact page index descriptor"));
            }
            let index_value = self.read_work_object(index.artifact_root()).await?;
            let pages = validate_artifact_page_index(&index_value, &artifact, page_cap)?;
            output.push(index);
            output.extend(pages);
        }
        output.sort_by_key(descriptor_sort_key);
        output.dedup();
        Ok(output)
    }

    /// Return only v3 page/index descriptors authenticated by the frozen
    /// graph work image and its registered source-capture and graph-context
    /// roots. This function is read-only; inspection performs current policy
    /// authorization before disclosing any returned descriptor.
    pub(crate) async fn graph_artifact_page_descriptors(
        &self,
        job: &JobId,
    ) -> Result<Vec<SourcePlusGraphArtifactDescriptor>> {
        let Some(catalog_root) = self.work.get(job, "graph_artifact_pages")? else {
            return Ok(Vec::new());
        };
        let draft = self
            .work_value(job, "evaluation")
            .await?
            .ok_or_else(|| Error::invalid("missing frozen acquisition evaluation"))?;
        if draft.field("job_id")?.as_str()? != job.as_str()
            || draft.field("schema")?.as_str()? != "ctxql-acquisition-graph-work/v1"
        {
            return Err(Error::invalid("graph acquisition work binding"));
        }
        let originals = graph_artifact_descriptors(&draft, self.artifact_limit)?;
        let roots = self.authenticated_graph_artifact_roots(job, &draft, None)?;
        validate_graph_authority_union(&originals, &roots)?;
        let catalog = self.read_work_object(&catalog_root).await?;
        catalog.closed(&["schema", "job_id", "entries"], &[])?;
        if catalog.field("schema")?.as_str()?
            != "ctxql-acquisition-source-plus-graph-artifact-pages/v1"
            || catalog.field("job_id")?.as_str()? != job.as_str()
        {
            return Err(Error::invalid("graph artifact page catalog binding"));
        }
        let page_cap = artifact_page_cap(self.artifact_page_limit);
        let mut output = Vec::new();
        for entry in catalog.field("entries")?.as_array()? {
            entry.closed(&["authority", "artifact", "index"], &[])?;
            let authority = SourcePlusGraphArtifactDescriptor::from_value(
                entry.field("authority")?,
                self.artifact_limit,
            )?;
            if !originals.contains(&authority) {
                return Err(Error::invalid("graph artifact page authority"));
            }
            let artifact = SourcePlusGraphArtifactDescriptor::from_value(
                entry.field("artifact")?,
                self.artifact_limit,
            )?;
            validate_graph_paged_artifact_binding(&authority, &artifact, &roots)?;
            let index = SourcePlusGraphArtifactDescriptor::from_value(
                entry.field("index")?,
                self.artifact_limit,
            )?;
            if index != artifact.successor(index.artifact_root().clone(), "artifact_page_index")? {
                return Err(Error::invalid("graph artifact page index descriptor"));
            }
            let index_value = self.read_work_object(index.artifact_root()).await?;
            let pages = validate_graph_artifact_page_index(&index_value, &artifact, page_cap)?;
            output.push(index);
            output.extend(pages);
        }
        output.sort_by_key(graph_descriptor_sort_key);
        output.dedup();
        Ok(output)
    }

    async fn persist_artifact_pages(
        &self,
        job: &JobId,
        authorities: &[AcquisitionArtifactDescriptor],
        result_root: &ContentHash,
    ) -> Result<()> {
        if self.work.get(job, "artifact_pages")?.is_some() {
            self.artifact_page_descriptors(job).await?;
            return Ok(());
        }
        if authorities.is_empty() {
            return Ok(());
        }
        let mut targets = authorities
            .iter()
            .cloned()
            .map(|descriptor| (descriptor.clone(), descriptor))
            .collect::<Vec<_>>();
        let first = &authorities[0];
        if authorities.iter().all(|descriptor| {
            descriptor.source() == first.source()
                && descriptor.source_fragment_hash() == first.source_fragment_hash()
                && descriptor.context_root() == first.context_root()
        }) {
            for (stage, kind) in [
                ("capture", "provider_capture"),
                ("evaluation", "evaluation_checkpoint"),
                ("result", "admission_result"),
            ] {
                let root = if stage == "result" {
                    Some(result_root.clone())
                } else {
                    self.work.get(job, stage)?
                };
                if let Some(root) = root {
                    targets.push((first.clone(), first.successor(root, kind)?));
                }
            }
        }
        let page_cap = artifact_page_cap(self.artifact_page_limit);
        let mut aggregate_bytes = 0usize;
        let mut entries = Vec::new();
        for (authority, artifact) in targets {
            let object = self
                .source_reader
                .read(artifact.artifact_root(), self.artifact_limit)
                .await?;
            aggregate_bytes = aggregate_bytes
                .checked_add(object.bytes().len())
                .ok_or_else(Error::limit)?;
            if aggregate_bytes > self.artifact_limit {
                return Err(Error::limit());
            }
            if object.bytes().len() <= page_cap {
                continue;
            }
            let mut page_values = Vec::new();
            for (ordinal, bytes) in utf8_artifact_pages(object.bytes(), page_cap)?
                .into_iter()
                .enumerate()
            {
                let root = self.source_writer.put(bytes, page_cap).await?;
                page_values.push(V::object([
                    ("ordinal".into(), V::integer(ordinal as u64)),
                    ("root".into(), V::string(root.as_str())),
                    ("bytes".into(), V::integer(bytes.len() as u64)),
                ])?);
            }
            let index_value = V::object([
                (
                    "schema".into(),
                    V::string("ctxql-acquisition-artifact-page-index/v1"),
                ),
                ("artifact".into(), artifact.projection()),
                (
                    "total_bytes".into(),
                    V::integer(object.bytes().len() as u64),
                ),
                ("page_bytes".into(), V::integer(page_cap as u64)),
                ("pages".into(), V::Array(page_values)),
            ])?;
            let index_bytes = index_value.canonical_bytes(Limits::default())?;
            if index_bytes.len() > page_cap {
                return Err(Error::limit());
            }
            let index_root = self.source_writer.put(&index_bytes, page_cap).await?;
            let index_descriptor = artifact.successor(index_root, "artifact_page_index")?;
            entries.push(V::object([
                ("authority".into(), authority.projection()),
                ("artifact".into(), artifact.projection()),
                ("index".into(), index_descriptor.projection()),
            ])?);
        }
        if entries.is_empty() {
            return Ok(());
        }
        let catalog = V::object([
            (
                "schema".into(),
                V::string("ctxql-acquisition-artifact-pages/v1"),
            ),
            ("job_id".into(), V::string(job.as_str())),
            ("entries".into(), V::Array(entries)),
        ])?;
        let bytes = catalog.canonical_bytes(Limits::default())?;
        if bytes.len() > page_cap {
            return Err(Error::limit());
        }
        let root = self.source_writer.put(&bytes, page_cap).await?;
        self.work.put(job, "artifact_pages", &root)
    }

    async fn persist_graph_artifact_pages(
        &self,
        job: &JobId,
        draft: &V,
        authorities: &[SourcePlusGraphArtifactDescriptor],
        result_root: &ContentHash,
    ) -> Result<()> {
        if self.work.get(job, "graph_artifact_pages")?.is_some() {
            self.graph_artifact_page_descriptors(job).await?;
            return Ok(());
        }
        if authorities.is_empty() {
            return Ok(());
        }
        let roots = self.authenticated_graph_artifact_roots(job, draft, Some(result_root))?;
        validate_graph_authority_union(authorities, &roots)?;
        let first = &authorities[0];
        let mut targets = authorities
            .iter()
            .cloned()
            .map(|descriptor| (descriptor.clone(), descriptor))
            .collect::<Vec<_>>();
        for (root, kind) in &roots.targets {
            targets.push((first.clone(), first.successor(root.clone(), *kind)?));
        }

        let page_cap = artifact_page_cap(self.artifact_page_limit);
        let mut aggregate_bytes = 0usize;
        let mut entries = Vec::new();
        for (authority, artifact) in targets {
            let object = self
                .source_reader
                .read(artifact.artifact_root(), self.artifact_limit)
                .await?;
            aggregate_bytes = aggregate_bytes
                .checked_add(object.bytes().len())
                .ok_or_else(Error::limit)?;
            if aggregate_bytes > self.artifact_limit {
                return Err(Error::limit());
            }
            if object.bytes().len() <= page_cap {
                continue;
            }
            let mut page_values = Vec::new();
            for (ordinal, bytes) in utf8_artifact_pages(object.bytes(), page_cap)?
                .into_iter()
                .enumerate()
            {
                let root = self.source_writer.put(bytes, page_cap).await?;
                page_values.push(V::object([
                    ("ordinal".into(), V::integer(ordinal as u64)),
                    ("root".into(), V::string(root.as_str())),
                    ("bytes".into(), V::integer(bytes.len() as u64)),
                ])?);
            }
            let index_value = V::object([
                (
                    "schema".into(),
                    V::string("ctxql-acquisition-source-plus-graph-artifact-page-index/v1"),
                ),
                ("artifact".into(), artifact.projection()),
                (
                    "total_bytes".into(),
                    V::integer(object.bytes().len() as u64),
                ),
                ("page_bytes".into(), V::integer(page_cap as u64)),
                ("pages".into(), V::Array(page_values)),
            ])?;
            let index_bytes = index_value.canonical_bytes(Limits::default())?;
            if index_bytes.len() > page_cap {
                return Err(Error::limit());
            }
            let index_root = self.source_writer.put(&index_bytes, page_cap).await?;
            let index_descriptor = artifact.successor(index_root, "artifact_page_index")?;
            entries.push(V::object([
                ("authority".into(), authority.projection()),
                ("artifact".into(), artifact.projection()),
                ("index".into(), index_descriptor.projection()),
            ])?);
        }
        if entries.is_empty() {
            return Ok(());
        }
        let catalog = V::object([
            (
                "schema".into(),
                V::string("ctxql-acquisition-source-plus-graph-artifact-pages/v1"),
            ),
            ("job_id".into(), V::string(job.as_str())),
            ("entries".into(), V::Array(entries)),
        ])?;
        let bytes = catalog.canonical_bytes(Limits::default())?;
        if bytes.len() > page_cap {
            return Err(Error::limit());
        }
        let root = self.source_writer.put(&bytes, page_cap).await?;
        self.work.put(job, "graph_artifact_pages", &root)
    }

    fn authenticated_graph_artifact_roots(
        &self,
        job: &JobId,
        draft: &V,
        result_root: Option<&ContentHash>,
    ) -> Result<AuthenticatedGraphArtifactRoots> {
        let graph = draft.field("graph")?;
        graph.closed(
            &[
                "capture_root",
                "context_root",
                "workspace_root",
                "capability_root",
                "leaf_roots",
            ],
            &[],
        )?;
        let registered = |stage: &str, field: &str| -> Result<ContentHash> {
            let root = ContentHash::parse(graph.field(field)?.as_str()?)?;
            if self.work.get(job, stage)?.as_ref() != Some(&root) {
                return Err(Error::invalid("graph artifact registered root"));
            }
            Ok(root)
        };
        let source_capture_root = self
            .work
            .get(job, "capture")?
            .ok_or_else(|| Error::invalid("missing acquisition capture binding"))?;
        let graph_capture_root = registered("graph_capture", "capture_root")?;
        let graph_context_root = registered("graph_context", "context_root")?;
        let graph_workspace_root = registered("graph_workspace", "workspace_root")?;
        let _capability_root = registered("graph_capability", "capability_root")?;
        let evaluation_root = self
            .work
            .get(job, "evaluation")?
            .ok_or_else(|| Error::invalid("missing evaluation checkpoint"))?;
        let result_root = match result_root {
            Some(expected) => {
                if self.work.get(job, "result")?.as_ref() != Some(expected) {
                    return Err(Error::invalid("graph artifact result root"));
                }
                Some(expected.clone())
            }
            None => self.work.get(job, "result")?,
        };
        let mut targets = vec![
            (source_capture_root.clone(), "provider_graph_capture"),
            (graph_workspace_root, "graph_workspace"),
            (graph_context_root.clone(), "graph_context"),
            (graph_capture_root, "graph_capture_index"),
            (evaluation_root, "evaluation_checkpoint"),
        ];
        if let Some(root) = result_root {
            targets.push((root, "graph_admission_result"));
        }
        Ok(AuthenticatedGraphArtifactRoots {
            source_capture_root,
            graph_context_root,
            targets,
        })
    }
}

struct AuthenticatedGraphArtifactRoots {
    source_capture_root: ContentHash,
    graph_context_root: ContentHash,
    targets: Vec<(ContentHash, &'static str)>,
}

const ARTIFACT_PAGE_TARGET_BYTES: usize = 256 * 1024;

fn utf8_artifact_pages(bytes: &[u8], cap: usize) -> Result<Vec<&[u8]>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::invalid("acquisition artifact is not UTF-8"))?;
    let mut pages = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let mut end = start.saturating_add(cap).min(bytes.len());
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            return Err(Error::limit());
        }
        pages.push(&bytes[start..end]);
        start = end;
    }
    Ok(pages)
}

fn artifact_page_cap(source_read_cap: usize) -> usize {
    source_read_cap
        .min(Limits::default().input_bytes())
        .min(ARTIFACT_PAGE_TARGET_BYTES)
}

fn descriptor_sort_key(descriptor: &AcquisitionArtifactDescriptor) -> String {
    descriptor_projection_sort_key(&descriptor.projection())
}

fn graph_descriptor_sort_key(descriptor: &SourcePlusGraphArtifactDescriptor) -> String {
    descriptor_projection_sort_key(&descriptor.projection())
}

fn descriptor_projection_sort_key(projection: &V) -> String {
    ContentHash::of_bytes(
        &projection
            .canonical_bytes(Limits::default())
            .expect("descriptor canonical value"),
    )
    .as_str()
    .to_owned()
}

fn validate_graph_authority_union(
    authorities: &[SourcePlusGraphArtifactDescriptor],
    roots: &AuthenticatedGraphArtifactRoots,
) -> Result<()> {
    let Some(first) = authorities.first() else {
        return Ok(());
    };
    if first.context_root() != &roots.source_capture_root
        || first.graph_context_root() != &roots.graph_context_root
    {
        return Err(Error::invalid("graph artifact authority roots"));
    }
    if authorities.iter().any(|descriptor| {
        descriptor.source() != first.source()
            || descriptor.source_fragment_hash() != first.source_fragment_hash()
            || descriptor.context_root() != first.context_root()
            || descriptor.graph_context_root() != first.graph_context_root()
    }) {
        return Err(Error::invalid(
            "mixed graph artifact restrictions cannot be represented",
        ));
    }
    Ok(())
}

fn validate_graph_paged_artifact_binding(
    authority: &SourcePlusGraphArtifactDescriptor,
    artifact: &SourcePlusGraphArtifactDescriptor,
    roots: &AuthenticatedGraphArtifactRoots,
) -> Result<()> {
    if artifact == authority
        || roots.targets.iter().any(|(root, kind)| {
            authority
                .successor(root.clone(), *kind)
                .is_ok_and(|expected| &expected == artifact)
        })
    {
        return Ok(());
    }
    Err(Error::invalid("paged graph artifact binding"))
}

fn validate_paged_artifact_binding(
    service: &AcquisitionService,
    job: &JobId,
    authority: &AcquisitionArtifactDescriptor,
    artifact: &AcquisitionArtifactDescriptor,
) -> Result<()> {
    if artifact == authority {
        return Ok(());
    }
    for (stage, kind) in [
        ("capture", "provider_capture"),
        ("evaluation", "evaluation_checkpoint"),
        ("result", "admission_result"),
    ] {
        if let Some(root) = service.work.get(job, stage)? {
            if artifact == &authority.successor(root, kind)? {
                return Ok(());
            }
        }
    }
    Err(Error::invalid("paged artifact binding"))
}

fn validate_artifact_page_index(
    value: &V,
    artifact: &AcquisitionArtifactDescriptor,
    page_cap: usize,
) -> Result<Vec<AcquisitionArtifactDescriptor>> {
    value.closed(
        &["schema", "artifact", "total_bytes", "page_bytes", "pages"],
        &[],
    )?;
    if value.field("schema")?.as_str()? != "ctxql-acquisition-artifact-page-index/v1"
        || value.field("artifact")? != &artifact.projection()
        || usize::try_from(value.field("page_bytes")?.u64()?).map_err(|_| Error::limit())?
            != page_cap
    {
        return Err(Error::invalid("artifact page index binding"));
    }
    let pages = value.field("pages")?.as_array()?;
    if pages.len() < 2 {
        return Err(Error::invalid("artifact page count"));
    }
    let mut descriptors = Vec::with_capacity(pages.len());
    let mut total = 0usize;
    for (ordinal, page) in pages.iter().enumerate() {
        page.closed(&["ordinal", "root", "bytes"], &[])?;
        let bytes = usize::try_from(page.field("bytes")?.u64()?).map_err(|_| Error::limit())?;
        if usize::try_from(page.field("ordinal")?.u64()?).map_err(|_| Error::limit())? != ordinal
            || bytes == 0
            || bytes > page_cap
            || (ordinal + 1 < pages.len() && bytes < page_cap.saturating_sub(3))
        {
            return Err(Error::invalid("artifact page index entry"));
        }
        let root = ContentHash::parse(page.field("root")?.as_str()?)?;
        descriptors.push(artifact.successor(root, "artifact_page")?);
        total = total.checked_add(bytes).ok_or_else(Error::limit)?;
    }
    if total != usize::try_from(value.field("total_bytes")?.u64()?).map_err(|_| Error::limit())?
        || total <= page_cap
    {
        return Err(Error::invalid("artifact page total"));
    }
    Ok(descriptors)
}

fn validate_graph_artifact_page_index(
    value: &V,
    artifact: &SourcePlusGraphArtifactDescriptor,
    page_cap: usize,
) -> Result<Vec<SourcePlusGraphArtifactDescriptor>> {
    value.closed(
        &["schema", "artifact", "total_bytes", "page_bytes", "pages"],
        &[],
    )?;
    if value.field("schema")?.as_str()?
        != "ctxql-acquisition-source-plus-graph-artifact-page-index/v1"
        || value.field("artifact")? != &artifact.projection()
        || usize::try_from(value.field("page_bytes")?.u64()?).map_err(|_| Error::limit())?
            != page_cap
    {
        return Err(Error::invalid("graph artifact page index binding"));
    }
    let pages = value.field("pages")?.as_array()?;
    if pages.len() < 2 {
        return Err(Error::invalid("graph artifact page count"));
    }
    let mut descriptors = Vec::with_capacity(pages.len());
    let mut total = 0usize;
    for (ordinal, page) in pages.iter().enumerate() {
        page.closed(&["ordinal", "root", "bytes"], &[])?;
        let bytes = usize::try_from(page.field("bytes")?.u64()?).map_err(|_| Error::limit())?;
        if usize::try_from(page.field("ordinal")?.u64()?).map_err(|_| Error::limit())? != ordinal
            || bytes == 0
            || bytes > page_cap
            || (ordinal + 1 < pages.len() && bytes < page_cap.saturating_sub(3))
        {
            return Err(Error::invalid("graph artifact page index entry"));
        }
        let root = ContentHash::parse(page.field("root")?.as_str()?)?;
        descriptors.push(artifact.successor(root, "artifact_page")?);
        total = total.checked_add(bytes).ok_or_else(Error::limit)?;
    }
    if total != usize::try_from(value.field("total_bytes")?.u64()?).map_err(|_| Error::limit())?
        || total <= page_cap
    {
        return Err(Error::invalid("graph artifact page total"));
    }
    Ok(descriptors)
}

fn acquisition_artifact_descriptors(
    draft: &V,
    max_bytes: usize,
) -> Result<Vec<AcquisitionArtifactDescriptor>> {
    draft
        .field("report")?
        .as_object()?
        .get("artifact_descriptors")
        .map(|values| {
            values
                .as_array()?
                .iter()
                .map(|value| AcquisitionArtifactDescriptor::from_value(value, max_bytes))
                .collect()
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn graph_artifact_descriptors(
    draft: &V,
    max_bytes: usize,
) -> Result<Vec<SourcePlusGraphArtifactDescriptor>> {
    match &draft {
        V::Object(fields) => fields
            .get("graph_artifact_descriptors")
            .map(|values| {
                values
                    .as_array()?
                    .iter()
                    .map(|value| SourcePlusGraphArtifactDescriptor::from_value(value, max_bytes))
                    .collect()
            })
            .transpose()
            .map(Option::unwrap_or_default),
        _ => Err(Error::invalid("acquisition work shape")),
    }
}

fn recovery_key(stage: &str, predecessor: &BundleId, capture: &SnapshotRef) -> Result<ContentHash> {
    Ok(ContentHash::of_bytes(
        &V::Array(vec![
            V::string("ctxql-stale-absent-successor/v1"),
            V::string(stage),
            V::string(predecessor.as_str()),
            capture.projection(),
        ])
        .canonical_bytes(Limits::default())?,
    ))
}

fn review_successor(
    predecessor: &ValidatedReviewBundle,
    capture: SnapshotRef,
) -> Result<ValidatedReviewBundle> {
    let key = recovery_key("review", predecessor.id(), &capture)?;
    let records = predecessor
        .records()
        .iter()
        .map(|record| {
            let id = ContentHash::of_bytes(
                format!(
                    "ctxql-review-stale-successor/v1\0{}\0{}",
                    key.as_str(),
                    record.id().as_str()
                )
                .as_bytes(),
            );
            ReviewRecord::new(
                ReviewRecordId::new(format!("urn:ctxql:review:successor:{}", &id.as_str()[7..]))?,
                record.component_ref(),
                record.source_ref(),
                record.artifact_root().clone(),
                record.vocabulary_verdict(),
                record.assertion_intent(),
                record.reason_codes().to_vec(),
                record.suggested_predicates().to_vec(),
                record.suggested_types().to_vec(),
                record.resolved_predicates().to_vec(),
                record.resolved_types().to_vec(),
                record.accepted_claim_ids().to_vec(),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    ValidatedReviewBundle::new(
        BundleId::new(format!("bundle:review:successor:{}", &key.as_str()[7..]))?,
        predecessor.evaluation_id(),
        predecessor.logical_bundle_key(),
        AttemptId::new(format!("attempt:review:successor:{}", &key.as_str()[7..]))?,
        capture,
        records,
        Limits::default(),
    )
}

fn business_successor(
    predecessor: &ValidatedSemanticBundle,
    capture: SnapshotRef,
) -> Result<ValidatedSemanticBundle> {
    let key = recovery_key("business", predecessor.id(), &capture)?;
    let descriptor = predecessor.projection().field("descriptor")?.clone();
    ValidatedSemanticBundle::new(
        BundleId::new(format!("bundle:business:successor:{}", &key.as_str()[7..]))?,
        predecessor.extraction_run().clone(),
        capture,
        descriptor,
        predecessor
            .claim_roles()
            .iter()
            .cloned()
            .zip(predecessor.claims().iter().cloned())
            .collect(),
        Limits::default(),
    )
}

fn bundle_attempt_id(bundle: &ValidatedSemanticBundle) -> Result<AttemptId> {
    let key = ContentHash::of_bytes(
        format!("ctxql-business-attempt/v1\0{}", bundle.id().as_str()).as_bytes(),
    );
    AttemptId::new(format!("attempt:business:{}", &key.as_str()[7..]))
}

fn superseded_record(
    job: &JobId,
    kind: SupersededPreparedKind,
    predecessor_bundle: &BundleId,
    predecessor_attempt: &AttemptId,
    successor_bundle: &BundleId,
    successor_attempt: &AttemptId,
    successor_capture: SnapshotRef,
) -> Result<PreparedSupersededAbsent> {
    let record = PreparedSupersededAbsent {
        job_id: job.clone(),
        kind,
        predecessor_bundle_id: predecessor_bundle.clone(),
        predecessor_attempt_id: predecessor_attempt.clone(),
        successor_bundle_id: successor_bundle.clone(),
        successor_attempt_id: successor_attempt.clone(),
        successor_capture,
        recorded_at: work_timestamp()?,
    };
    record.validate()?;
    Ok(record)
}

fn verify_review_supersession(
    job: &JobId,
    predecessor: &ValidatedReviewBundle,
    record: &PreparedSupersededAbsent,
) -> Result<()> {
    let successor = review_successor(predecessor, record.successor_capture.clone())?;
    if record.job_id != *job
        || record.kind != SupersededPreparedKind::Review
        || record.predecessor_bundle_id != *predecessor.id()
        || record.predecessor_attempt_id != *predecessor.attempt_id()
        || record.successor_bundle_id != *successor.id()
        || record.successor_attempt_id != *successor.attempt_id()
    {
        return Err(Error::new(
            ErrorKind::Conflict,
            "review prepared supersession binding mismatch",
        ));
    }
    Ok(())
}

fn verify_business_supersession(
    job: &JobId,
    prepared: &BundlePrepared,
    predecessor: &ValidatedSemanticBundle,
    record: &PreparedSupersededAbsent,
) -> Result<()> {
    let successor = business_successor(predecessor, record.successor_capture.clone())?;
    if record.job_id != *job
        || record.kind != SupersededPreparedKind::Business
        || record.predecessor_bundle_id != prepared.bundle_id
        || record.predecessor_attempt_id != prepared.attempt_id
        || record.successor_bundle_id != *successor.id()
        || record.successor_attempt_id != bundle_attempt_id(&successor)?
    {
        return Err(Error::new(
            ErrorKind::Conflict,
            "business prepared supersession binding mismatch",
        ));
    }
    Ok(())
}

fn verify_business_receipt(
    prepared: &BundlePrepared,
    receipt: &SemanticAdmissionReceipt,
) -> Result<()> {
    if receipt.payload_root() != &prepared.payload_root
        || receipt.projection().field("descriptor_root")?.as_str()?
            != prepared.descriptor_root.as_str()
        || receipt.claim_ids() != prepared.expected_claim_ids
    {
        return Err(Error::new(
            ErrorKind::Conflict,
            "work business receipt differs",
        ));
    }
    Ok(())
}

fn work_timestamp() -> Result<Timestamp> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::invalid("acquisition clock before epoch"))?
        .as_millis();
    Timestamp::from_millis(i64::try_from(millis).map_err(|_| Error::limit())?)
}

fn decode_business(stored: &V) -> Result<ValidatedSemanticBundle> {
    stored.closed(&["backend", "bundle"], &[])?;
    let value = stored.field("bundle")?;
    let capture = value.field("validation_capture")?;
    let claims = value
        .field("claims")?
        .as_array()?
        .iter()
        .map(|value| {
            Ok((
                value.field("role")?.as_str()?.to_owned(),
                CandidateClaim::from_value(value.field("claim")?)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let bundle = ValidatedSemanticBundle::new(
        BundleId::new(value.field("bundle_id")?.as_str()?)?,
        ExtractionRunId::new(value.field("extraction_run")?.as_str()?)?,
        SnapshotRef::new(
            BackendId::new(stored.field("backend")?.as_str()?)?,
            GraphPin::from_value(capture)?,
        ),
        value.field("descriptor")?.clone(),
        claims,
        Limits::default(),
    )?;
    if &bundle.projection() != value {
        return Err(Error::invalid("stored business bundle commitment"));
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod graph_page_tests {
    use super::*;
    use crate::acquisition_v2_fixture::AcquisitionV2Fixture;
    use cdb_core::{
        acquisition::SourceObjectWriter, contracts::IoFuture, evidence::EvidenceSelector,
        id::SourceId, source::SourceReadRequest,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct FailPut {
        inner: Arc<dyn SourceObjectWriter>,
        calls: AtomicUsize,
        fail_at: usize,
    }

    impl SourceObjectWriter for FailPut {
        fn put<'a>(&'a self, bytes: &'a [u8], max_bytes: usize) -> IoFuture<'a, ContentHash> {
            if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_at {
                return Box::pin(async { Err(Error::new(ErrorKind::Backend, "injected failure")) });
            }
            self.inner.put(bytes, max_bytes)
        }
    }

    async fn graph_draft(
        service: &AcquisitionService,
        job: &JobId,
        outcome: &[u8],
    ) -> (V, SourcePlusGraphArtifactDescriptor) {
        let capture_root = service
            .seal_work_value(job, "capture", &V::string("provider capture"))
            .await
            .unwrap();
        let workspace_root = service
            .seal_work_value(job, "graph_workspace", &V::string("workspace"))
            .await
            .unwrap();
        let context_root = service
            .seal_work_value(job, "graph_context", &V::string("graph context"))
            .await
            .unwrap();
        let capability_root = service
            .seal_work_value(job, "graph_capability", &V::string("capability"))
            .await
            .unwrap();
        let graph_capture_root = service
            .seal_work_value(job, "graph_capture", &V::string("graph capture index"))
            .await
            .unwrap();
        let outcome_root = service
            .source_writer
            .put(outcome, service.artifact_limit)
            .await
            .unwrap();
        let descriptor = SourcePlusGraphArtifactDescriptor::new(
            SourceReadRequest {
                source_id: SourceId::new(format!("urn:source:{}", job.as_str())).unwrap(),
                version: ContentHash::of_bytes(b"source version"),
                selector: EvidenceSelector::WholeDocument,
                max_bytes: service.artifact_limit,
            },
            ContentHash::of_bytes(b"source fragment"),
            outcome_root,
            "evaluation_outcomes",
            capture_root,
            context_root.clone(),
        )
        .unwrap();
        let draft = V::object([
            (
                "schema".into(),
                V::string("ctxql-acquisition-graph-work/v1"),
            ),
            ("job_id".into(), V::string(job.as_str())),
            (
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
                    ("leaf_roots".into(), V::Array(Vec::new())),
                ])
                .unwrap(),
            ),
            (
                "graph_artifact_descriptors".into(),
                V::Array(vec![descriptor.projection()]),
            ),
        ])
        .unwrap();
        service
            .seal_work_value(job, "evaluation", &draft)
            .await
            .unwrap();
        (draft, descriptor)
    }

    #[test]
    fn v3_successors_inherit_source_and_both_context_restrictions() {
        let descriptor = SourcePlusGraphArtifactDescriptor::new(
            SourceReadRequest {
                source_id: SourceId::new("urn:source:v3-inheritance").unwrap(),
                version: ContentHash::of_bytes(b"version"),
                selector: EvidenceSelector::WholeDocument,
                max_bytes: 1024,
            },
            ContentHash::of_bytes(b"fragment"),
            ContentHash::of_bytes(b"artifact"),
            "evaluation_outcomes",
            ContentHash::of_bytes(b"capture"),
            ContentHash::of_bytes(b"graph context"),
        )
        .unwrap();
        let successor = descriptor
            .successor(ContentHash::of_bytes(b"page"), "artifact_page")
            .unwrap();
        assert_eq!(successor.source(), descriptor.source());
        assert_eq!(
            successor.source_fragment_hash(),
            descriptor.source_fragment_hash()
        );
        assert_eq!(successor.context_root(), descriptor.context_root());
        assert_eq!(
            successor.graph_context_root(),
            descriptor.graph_context_root()
        );
    }

    #[test]
    fn v3_rejects_forged_graph_root_and_mixed_restrictions() {
        let make = |source: &str, graph: &[u8]| {
            SourcePlusGraphArtifactDescriptor::new(
                SourceReadRequest {
                    source_id: SourceId::new(source).unwrap(),
                    version: ContentHash::of_bytes(b"version"),
                    selector: EvidenceSelector::WholeDocument,
                    max_bytes: 1024,
                },
                ContentHash::of_bytes(b"fragment"),
                ContentHash::of_bytes(source.as_bytes()),
                "evaluation_outcomes",
                ContentHash::of_bytes(b"capture"),
                ContentHash::of_bytes(graph),
            )
            .unwrap()
        };
        let roots = AuthenticatedGraphArtifactRoots {
            source_capture_root: ContentHash::of_bytes(b"capture"),
            graph_context_root: ContentHash::of_bytes(b"graph"),
            targets: Vec::new(),
        };
        assert!(
            validate_graph_authority_union(&[make("urn:source:one", b"forged")], &roots).is_err()
        );
        assert!(validate_graph_authority_union(
            &[
                make("urn:source:one", b"graph"),
                make("urn:source:two", b"graph")
            ],
            &roots
        )
        .is_err());
    }

    #[tokio::test]
    async fn v3_pages_preserve_utf8_reconstruct_and_retry_idempotently() {
        let fixture = AcquisitionV2Fixture::create().await.unwrap();
        let config = fixture.config().unwrap();
        let job = JobId::new("job:v3-graph-pages-retry").unwrap();
        let mut service = AcquisitionService::open(&config, fixture.catalog_identity().clone())
            .await
            .unwrap();
        let text = format!(
            "{}🙂é終{}",
            "x".repeat(ARTIFACT_PAGE_TARGET_BYTES - 1),
            "z".repeat(31)
        );
        let (draft, authority) = graph_draft(&service, &job, text.as_bytes()).await;
        let result_root = service
            .seal_work_value(&job, "result", &V::string("result"))
            .await
            .unwrap();
        let real_writer = service.source_writer.clone();
        Arc::get_mut(&mut service).unwrap().source_writer = Arc::new(FailPut {
            inner: real_writer.clone(),
            calls: AtomicUsize::new(0),
            fail_at: 3,
        });
        assert!(service
            .persist_graph_artifact_pages(
                &job,
                &draft,
                std::slice::from_ref(&authority),
                &result_root,
            )
            .await
            .is_err());
        assert!(service
            .work
            .get(&job, "graph_artifact_pages")
            .unwrap()
            .is_none());
        Arc::get_mut(&mut service).unwrap().source_writer = real_writer;
        service
            .persist_graph_artifact_pages(
                &job,
                &draft,
                std::slice::from_ref(&authority),
                &result_root,
            )
            .await
            .unwrap();
        service
            .persist_graph_artifact_pages(
                &job,
                &draft,
                std::slice::from_ref(&authority),
                &result_root,
            )
            .await
            .unwrap();
        let descriptors = service.graph_artifact_page_descriptors(&job).await.unwrap();
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
                    && descriptor.source() == authority.source()
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
        assert_eq!(reconstructed, text.as_bytes());
        assert!(descriptors.iter().all(|descriptor| {
            descriptor.context_root() == authority.context_root()
                && descriptor.graph_context_root() == authority.graph_context_root()
        }));
        service.shutdown().await.unwrap();
    }
}
