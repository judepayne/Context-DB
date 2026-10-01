//! Narrow file-backed semantic write capability for trusted acquisition.

use crate::review_codec::{
    decode_review, encode_review_bundle, ExactReviewTerm, RdfReviewDocument, ReviewCodecLimits,
    RECORD_MARKER,
};
use crate::semantic::{semantic_commit_timestamp, FlureeSemanticLedger, SemanticLedgerOptions};
use crate::semantic_codec::{
    decode_claim, encode_bundle, ExactRdfTerm, MetadataFact, RdfClaimDocument, SemanticCodecLimits,
    NS,
};
use crate::semantic_policy::{verify_semantic_authority_current, SemanticPolicyBasis};
use crate::semantic_preparation::{prepare_historical_authorized_view, ExtractionLimits};
use cdb_core::acquisition::{
    AdmissionRecovery, BundlePrepared, ReviewAdmissionRecovery, SemanticBundleWriter,
};
use cdb_core::admission::ExportRecord;
use cdb_core::claim::CandidateClaim;
use cdb_core::contracts::{IoFuture, SemanticProjectionSource};
use cdb_core::id::{ContentHash, Iri, ResourceId, VersionId};
use cdb_core::ontology_catalog::OntologyCatalogIdentity;
use cdb_core::review::{
    canonical_review_root, ReviewAdmissionReceipt, ReviewBundlePrepared, ValidatedReviewBundle,
};
use cdb_core::semantic_admission::{
    canonical_claim_root, SemanticAdmissionReceipt, ValidatedSemanticBundle,
};
use cdb_core::snapshot::{GraphPin, SnapshotRef};
use cdb_core::{CanonicalValue as V, Error, ErrorKind, Limits, Result};
use fluree_db_api::{Fluree, FlureeBuilder, GraphDb, LedgerState, ResolvedValue};
use fs2::FileExt;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};

#[derive(Clone, Debug)]
pub struct SemanticWriterOptions {
    pub reader: SemanticLedgerOptions,
    pub claims_graph: Iri,
    pub review_graph: Iri,
    pub codec_limits: SemanticCodecLimits,
    pub review_codec_limits: ReviewCodecLimits,
    pub extraction_limits: ExtractionLimits,
    pub authority: SemanticPolicyBasis,
}

/// Deliberately does not implement any query-service source trait. Only the
/// acquisition composition root receives this value.
pub struct FlureeSemanticWriter {
    writer: Arc<Fluree>,
    reader: FlureeSemanticLedger,
    options: SemanticWriterOptions,
    serial: Mutex<()>,
    _process_lease: File,
}

/// A bounded lock-held facade for review-first workflows. It lets orchestration
/// recover/commit review, capture the resulting head, and then recover/commit
/// business without another participating writer entering between those steps.
pub struct FlureeWriterSession<'a> {
    writer: &'a FlureeSemanticWriter,
    _guard: MutexGuard<'a, ()>,
}

/// Opaque proof that the sole Semantic writer is fenced and every retained
/// support is currently visible to the extraction principal.
pub struct SemanticDisclosureGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

impl FlureeSemanticWriter {
    pub async fn open_file(path: impl AsRef<Path>, options: SemanticWriterOptions) -> Result<Self> {
        let path = path.as_ref();
        let lock_path = path.join(".ctxql-acquisition-writer-v1.lock");
        let mut lock_options = OpenOptions::new();
        lock_options.create(true).read(true).write(true);
        #[cfg(unix)]
        lock_options.mode(0o600);
        let process_lease = lock_options
            .open(lock_path)
            .map_err(|_| Error::new(ErrorKind::Backend, "semantic writer lease storage"))?;
        process_lease.try_lock_exclusive().map_err(|_| {
            Error::new(
                ErrorKind::Conflict,
                "semantic acquisition writer lease unavailable",
            )
        })?;
        let writer = Arc::new(
            FlureeBuilder::file(path.to_string_lossy().into_owned())
                .without_indexing()
                .build()
                .map_err(map_backend)?,
        );
        // Both opens must resolve the same existing ledger. R2 proves this
        // direct writer/read-only-reader ownership mode on the pinned backend.
        writer
            .ledger(options.reader.ledger.as_str())
            .await
            .map_err(map_backend)?;
        let reader = FlureeSemanticLedger::open_file(path, options.reader.clone()).await?;
        Ok(Self {
            writer,
            reader,
            options,
            serial: Mutex::new(()),
            _process_lease: process_lease,
        })
    }

    pub fn authority_basis(&self) -> &SemanticPolicyBasis {
        &self.options.authority
    }

    pub async fn session(&self) -> FlureeWriterSession<'_> {
        FlureeWriterSession {
            writer: self,
            _guard: self.serial.lock().await,
        }
    }

    async fn authorize_disclosure_locked(
        &self,
        principal: &str,
        action: &str,
        policy_basis: &SemanticPolicyBasis,
        supports: &BTreeSet<String>,
    ) -> Result<()> {
        const MAX_DISCLOSED_SUPPORTS: usize = 4_096;
        const MAX_DISCLOSED_SUPPORT_BYTES: usize = 256 * 1024;
        if supports.len() > MAX_DISCLOSED_SUPPORTS
            || supports
                .iter()
                .try_fold(0usize, |total, value| total.checked_add(value.len()))
                .is_none_or(|bytes| bytes > MAX_DISCLOSED_SUPPORT_BYTES)
        {
            return Err(Error::limit());
        }
        verify_semantic_authority_current(&self.reader, policy_basis)
            .await
            .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
        let captured = SemanticProjectionSource::capture(&self.reader, None).await?;
        let t = captured
            .snapshot
            .pin()
            .revision()
            .as_str()
            .parse::<i64>()
            .map_err(|_| Error::invalid("semantic transaction"))?;
        let capture = self
            .reader
            .capture_at_t(t, Some(captured.snapshot.pin().receipt()), None)
            .await?;
        let current = prepare_historical_authorized_view(
            &self.reader,
            &capture,
            principal,
            action,
            self.options.extraction_limits,
        )
        .await
        .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
        if !supports.is_subset(&current.manifest.visible_supports) {
            return Err(Error::new(
                ErrorKind::Denied,
                "semantic disclosure dependency unavailable",
            ));
        }
        Ok(())
    }

    /// Hold the sole-writer serial fence through publication by the caller.
    pub async fn disclosure_guard(
        &self,
        principal: &str,
        action: &str,
        policy_basis: &SemanticPolicyBasis,
        supports: &BTreeSet<String>,
    ) -> Result<SemanticDisclosureGuard<'_>> {
        let guard = self.serial.lock().await;
        self.authorize_disclosure_locked(principal, action, policy_basis, supports)
            .await?;
        Ok(SemanticDisclosureGuard { _guard: guard })
    }

    /// Admission variant used by graph-backed extraction. Exact dependency
    /// authorization and recovery/admission share the sole-writer fence.
    pub async fn recover_or_admit_with_disclosure(
        &self,
        principal: &str,
        action: &str,
        policy_basis: &SemanticPolicyBasis,
        supports: &BTreeSet<String>,
        prepared: &BundlePrepared,
        bundle: &ValidatedSemanticBundle,
    ) -> Result<SemanticAdmissionReceipt> {
        let _guard = self.serial.lock().await;
        self.authorize_disclosure_locked(principal, action, policy_basis, supports)
            .await?;
        match self.recover_prepared(prepared).await? {
            AdmissionRecovery::Exact(receipt) => Ok(*receipt),
            AdmissionRecovery::Absent => self.admit_once(prepared, bundle).await,
            AdmissionRecovery::Conflict => Err(Error::new(
                ErrorKind::Conflict,
                "semantic admission recovery conflict",
            )),
        }
    }

    /// Bind acquisition startup to the exact certified ontology/catalog
    /// capture on this same Semantic Ledger before any admission capability is
    /// returned to the foreground pipeline.
    pub async fn verify_catalog_identity(&self, identity: &OntologyCatalogIdentity) -> Result<()> {
        let capture = identity.capture();
        if (identity.profile_identity()
            != cdb_core::recording_v4::ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID
            && identity.profile_identity()
                != cdb_core::recording_v5::CURRENT_ACQUISITION_PROFILE_ID)
            || capture.backend() != &self.options.reader.backend
            || capture.pin().authority() != &self.options.reader.authority
            || capture.pin().graph() != &self.options.reader.ledger
        {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "ontology catalog capture mismatch",
            ));
        }
        let t = capture
            .pin()
            .revision()
            .as_str()
            .parse::<i64>()
            .map_err(|_| Error::invalid("semantic transaction"))?;
        self.reader
            .capture_at_t(t, Some(capture.pin().receipt()), None)
            .await?;
        Ok(())
    }

    async fn verify_capture(&self, pin: &SnapshotRef) -> Result<()> {
        verify_semantic_authority_current(&self.reader, &self.options.authority)
            .await
            .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
        if pin.backend() != &self.options.reader.backend
            || pin.pin().authority() != &self.options.reader.authority
            || pin.pin().graph() != &self.options.reader.ledger
        {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "semantic_snapshot_divergence",
            ));
        }
        let current = self.reader.capture_current(None).await?;
        if current.snapshot() != pin {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "stale semantic validation capture",
            ));
        }
        let t = pin
            .pin()
            .revision()
            .as_str()
            .parse::<i64>()
            .map_err(|_| Error::invalid("semantic transaction"))?;
        self.reader
            .capture_at_t(t, Some(pin.pin().receipt()), None)
            .await?;
        Ok(())
    }

    async fn verify_validation_capture(&self, bundle: &ValidatedSemanticBundle) -> Result<()> {
        self.verify_capture(bundle.validation_capture()).await
    }

    async fn observed_claims_at_head(&self) -> Result<Vec<CandidateClaim>> {
        let state = self
            .writer
            .ledger(self.options.reader.ledger.as_str())
            .await
            .map_err(map_backend)?;
        self.read_claims(&state).await
    }

    async fn read_claims(&self, state: &LedgerState) -> Result<Vec<CandidateClaim>> {
        let graph = self.options.claims_graph.as_str();
        let query = format!(
            r#"
            PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
            PREFIX c: <{NS}>
            SELECT ?claim ?s ?p ?o ?relationType ?subjectType ?objectType ?claimType
                   ?confidence ?grounding ?lineage ?extensions ?validTime ?sourceObservedAt
            WHERE {{
              GRAPH <{graph}> {{
                ?claim rdf:reifies <<( ?s ?p ?o )>> ;
                  rdf:type c:Claim ;
                  c:relationType ?relationType ;
                  c:subjectType ?subjectType ;
                  c:objectType ?objectType ;
                  c:claimType ?claimType ;
                  c:confidence ?confidence ;
                  c:groundingLevel ?grounding ;
                  c:lineage ?lineage ;
                  c:extensions ?extensions .
                OPTIONAL {{ ?claim c:validTime ?validTime . }}
                OPTIONAL {{ ?claim c:sourceObservedAt ?sourceObservedAt . }}
              }}
            }} ORDER BY ?claim
            "#
        );
        let result = self
            .writer
            .query(&GraphDb::from_ledger_state(state), &query)
            .await
            .map_err(map_backend)?
            .to_sparql_json(&state.snapshot)
            .map_err(|_| Error::new(ErrorKind::Backend, "semantic admission readback format"))?;
        let rows = result
            .get("results")
            .and_then(|value| value.get("bindings"))
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| Error::new(ErrorKind::Backend, "semantic admission readback"))?;
        rows.iter()
            .map(|row| decode_readback_row(row, graph, self.options.codec_limits))
            .collect()
    }

    async fn recover_prepared(&self, prepared: &BundlePrepared) -> Result<AdmissionRecovery> {
        prepared.validate()?;
        let expected = prepared
            .expected_claim_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        let expected_ids = prepared
            .expected_claim_ids
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        let head = self
            .writer
            .ledger(self.options.reader.ledger.as_str())
            .await
            .map_err(map_backend)?;

        // V2 writes are proved by an attempt-bound marker and the claims in
        // that same native commit. A later commit containing equal stable
        // claim IDs is not evidence that an earlier attempt completed.
        let mut exact_marker = None;
        let mut marker_conflict = false;
        for t in 1..=head.t() {
            let detail = self
                .writer
                .graph(self.options.reader.ledger.as_str())
                .commit_t(t)
                .execute()
                .await
                .map_err(map_backend)?;
            match business_marker_match(&detail, prepared, self.options.review_graph.as_str())? {
                MarkerMatch::None => {}
                MarkerMatch::AttemptConflict => marker_conflict = true,
                MarkerMatch::Exact => {
                    if exact_marker.is_some() {
                        return Ok(AdmissionRecovery::Conflict);
                    }
                    exact_marker = Some(detail);
                }
            }
        }
        if marker_conflict {
            return Ok(AdmissionRecovery::Conflict);
        }
        if let Some(detail) = exact_marker {
            if commit_claim_ids(&detail, self.options.claims_graph.as_str()) != expected_ids {
                return Ok(AdmissionRecovery::Conflict);
            }
            let claims = decode_commit_claims(
                &detail,
                self.options.claims_graph.as_str(),
                self.options.codec_limits,
            )?;
            if claims.len() != expected.len()
                || claims.iter().any(|claim| !expected.contains(claim.id()))
                || canonical_claim_root(&claims, Limits::default())?
                    != prepared.canonical_claim_root
            {
                return Ok(AdmissionRecovery::Conflict);
            }
            return Ok(AdmissionRecovery::Exact(Box::new(business_receipt(
                prepared,
                &detail,
                &self.options,
            )?)));
        }

        let observed = self.observed_claims_at_head().await?;
        let matching = observed
            .iter()
            .filter(|claim| expected.contains(claim.id()))
            .collect::<Vec<_>>();
        // Stable acquisition-v2 IDs without this attempt's marker are a
        // collision or another attempt, never a recoverable acknowledgement.
        if prepared
            .expected_claim_ids
            .iter()
            .any(|id| id.as_str().starts_with("urn:ctxql:claim:v2:"))
        {
            return Ok(if matching.is_empty() {
                AdmissionRecovery::Absent
            } else {
                AdmissionRecovery::Conflict
            });
        }

        // Historical v1 bundles predate AdmissionCommit markers. Preserve
        // their claim-ID/root/history recovery behavior unchanged.
        if matching.is_empty() {
            return Ok(AdmissionRecovery::Absent);
        }
        if matching.len() != expected.len() {
            return Ok(AdmissionRecovery::Conflict);
        }
        let claims = matching.into_iter().cloned().collect::<Vec<_>>();
        if canonical_claim_root(&claims, Limits::default())? != prepared.canonical_claim_root {
            return Ok(AdmissionRecovery::Conflict);
        }
        let mut found = None;
        for t in 1..=head.t() {
            let detail = self
                .writer
                .graph(self.options.reader.ledger.as_str())
                .commit_t(t)
                .execute()
                .await
                .map_err(map_backend)?;
            let ids = commit_claim_ids(&detail, self.options.claims_graph.as_str())
                .into_iter()
                .filter(|id| expected_ids.contains(id))
                .collect::<std::collections::BTreeSet<_>>();
            if ids.is_empty() {
                continue;
            }
            if ids != expected_ids || found.is_some() {
                return Ok(AdmissionRecovery::Conflict);
            }
            found = Some(detail);
        }
        let Some(detail) = found else {
            return Ok(AdmissionRecovery::Conflict);
        };
        Ok(AdmissionRecovery::Exact(Box::new(business_receipt(
            prepared,
            &detail,
            &self.options,
        )?)))
    }

    async fn admit_once(
        &self,
        prepared: &BundlePrepared,
        bundle: &ValidatedSemanticBundle,
    ) -> Result<SemanticAdmissionReceipt> {
        self.verify_validation_capture(bundle).await?;
        let transaction = business_transaction(
            prepared,
            bundle,
            self.options.claims_graph.as_str(),
            self.options.review_graph.as_str(),
            self.options.codec_limits,
        )?;
        let before = self
            .writer
            .ledger(self.options.reader.ledger.as_str())
            .await
            .map_err(map_backend)?;
        let validation = bundle.validation_capture().pin();
        let expected_t = validation
            .revision()
            .as_str()
            .parse::<i64>()
            .map_err(|_| Error::invalid("semantic transaction"))?;
        if before.t() != expected_t
            || before
                .head_commit_id
                .as_ref()
                .map(ToString::to_string)
                .as_deref()
                != Some(validation.receipt().as_str())
        {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "semantic admission head changed before commit",
            ));
        }
        let committed = self
            .writer
            .insert(before, &transaction)
            .await
            .map_err(map_backend)?
            .ledger;
        let t = committed.t();
        let cid = ResourceId::new(
            committed
                .head_commit_id
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::Backend, "semantic commit has no CID"))?
                .to_string(),
        )?;
        let capture = self.reader.capture_current(None).await?;
        if capture.t() != u64::try_from(t).map_err(|_| Error::invalid("semantic transaction"))?
            || capture.commit_cid() != &cid
        {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "semantic_snapshot_divergence",
            ));
        }
        let expected = bundle
            .claims()
            .iter()
            .map(|claim| claim.id())
            .collect::<std::collections::BTreeSet<_>>();
        let observed = self
            .read_claims(&committed)
            .await?
            .into_iter()
            .filter(|claim| expected.contains(claim.id()))
            .collect::<Vec<_>>();
        let decoded_claim_root = canonical_claim_root(&observed, Limits::default())?;
        if observed.len() != expected.len() || decoded_claim_root != *bundle.canonical_claim_root()
        {
            return Err(Error::new(
                ErrorKind::Backend,
                "semantic admission readback mismatch",
            ));
        }
        let detail = self
            .writer
            .graph(self.options.reader.ledger.as_str())
            .commit_t(t)
            .execute()
            .await
            .map_err(map_backend)?;
        if detail.id != cid.as_str() {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "semantic_snapshot_divergence",
            ));
        }
        let stored_projection_root = commit_projection_root(&detail, Limits::default())?;
        let transaction_time = semantic_commit_timestamp(
            detail
                .time
                .as_deref()
                .ok_or_else(|| Error::invalid("semantic commit timestamp"))?,
        )?;
        SemanticAdmissionReceipt::new(
            bundle.admission_key().clone(),
            bundle.descriptor_root().clone(),
            bundle.payload_root().clone(),
            decoded_claim_root,
            stored_projection_root,
            capture.snapshot().clone(),
            transaction_time,
            bundle.expected_claim_ids(),
        )
    }

    /// Compatibility admission entry point. New orchestration should first
    /// persist `ReviewBundlePrepared` and call `recover_or_admit_review`.
    pub async fn admit_review(
        &self,
        bundle: &ValidatedReviewBundle,
    ) -> Result<ReviewAdmissionReceipt> {
        let session = self.session().await;
        session.admit_review_once(bundle).await
    }

    pub async fn recover_review(
        &self,
        prepared: &ReviewBundlePrepared,
    ) -> Result<ReviewAdmissionRecovery> {
        let session = self.session().await;
        session.recover_review(prepared).await
    }

    pub async fn recover_or_admit_review(
        &self,
        prepared: &ReviewBundlePrepared,
        bundle: &ValidatedReviewBundle,
    ) -> Result<ReviewAdmissionReceipt> {
        let session = self.session().await;
        session.recover_or_admit_review(prepared, bundle).await
    }

    async fn read_reviews(
        &self,
        state: &LedgerState,
    ) -> Result<Vec<cdb_core::review::ReviewRecord>> {
        let query = format!(
            "SELECT ?review ?p ?o WHERE {{ GRAPH <{}> {{ ?review <{}type> <{}> ; ?p ?o . }} }} ORDER BY ?review ?p ?o",
            self.options.review_graph.as_str(),
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
            RECORD_MARKER
        );
        let result = self
            .writer
            .query(&GraphDb::from_ledger_state(state), &query)
            .await
            .map_err(map_backend)?
            .to_sparql_json(&state.snapshot)
            .map_err(|_| Error::new(ErrorKind::Backend, "review readback format"))?;
        let rows = result
            .get("results")
            .and_then(|value| value.get("bindings"))
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| Error::new(ErrorKind::Backend, "review readback"))?;
        let mut documents =
            std::collections::BTreeMap::<String, Vec<crate::review_codec::ReviewFact>>::new();
        for row in rows {
            let review = bound(row, "review")?;
            let predicate = bound(row, "p")?;
            let object = review_bound_term(row, "o")?;
            documents
                .entry(review)
                .or_default()
                .push(crate::review_codec::ReviewFact {
                    graph: self.options.review_graph.as_str().to_owned(),
                    predicate,
                    object,
                });
        }
        documents
            .into_iter()
            .map(|(review_iri, facts)| {
                decode_review(
                    &RdfReviewDocument {
                        graph: self.options.review_graph.as_str().to_owned(),
                        review_iri,
                        facts,
                    },
                    self.options.review_codec_limits,
                )
            })
            .collect()
    }
}

impl FlureeWriterSession<'_> {
    /// Reauthorize every graph-context dependency while this session already
    /// owns the sole-writer fence. This is the lock-safe counterpart to
    /// `disclosure_guard`; callers must not try to acquire that guard from
    /// inside a writer session.
    pub async fn authorize_disclosure(
        &self,
        principal: &str,
        action: &str,
        policy_basis: &SemanticPolicyBasis,
        supports: &BTreeSet<String>,
    ) -> Result<()> {
        self.writer
            .authorize_disclosure_locked(principal, action, policy_basis, supports)
            .await
    }

    pub async fn capture_current(&self) -> Result<SnapshotRef> {
        Ok(self
            .writer
            .reader
            .capture_current(None)
            .await?
            .snapshot()
            .clone())
    }

    pub async fn recover_review(
        &self,
        prepared: &ReviewBundlePrepared,
    ) -> Result<ReviewAdmissionRecovery> {
        prepared.validate()?;
        let head = self
            .writer
            .writer
            .ledger(self.writer.options.reader.ledger.as_str())
            .await
            .map_err(map_backend)?;
        let mut exact = None;
        let mut saw_attempt_marker = false;
        for t in 1..=head.t() {
            let detail = self
                .writer
                .writer
                .graph(self.writer.options.reader.ledger.as_str())
                .commit_t(t)
                .execute()
                .await
                .map_err(map_backend)?;
            match marker_match(&detail, prepared, self.writer.options.review_graph.as_str())? {
                MarkerMatch::None => continue,
                MarkerMatch::AttemptConflict => saw_attempt_marker = true,
                MarkerMatch::Exact => {
                    if exact.is_some() {
                        return Ok(ReviewAdmissionRecovery::Conflict);
                    }
                    exact = Some(detail);
                }
            }
        }
        if saw_attempt_marker {
            return Ok(ReviewAdmissionRecovery::Conflict);
        }
        if let Some(detail) = exact {
            let records = decode_commit_reviews(
                &detail,
                self.writer.options.review_graph.as_str(),
                self.writer.options.review_codec_limits,
            )?;
            let ids = records
                .iter()
                .map(|record| record.id())
                .collect::<std::collections::BTreeSet<_>>();
            let expected_ids = prepared
                .expected_review_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>();
            if ids != expected_ids
                || records.len() != prepared.expected_review_ids.len()
                || canonical_review_root(&records, Limits::default())?
                    != prepared.canonical_review_root
            {
                return Ok(ReviewAdmissionRecovery::Conflict);
            }
            let capture = SnapshotRef::new(
                self.writer.options.reader.backend.clone(),
                GraphPin::new(
                    self.writer.options.reader.authority.clone(),
                    self.writer.options.reader.ledger.clone(),
                    VersionId::new(detail.t.to_string())?,
                    ResourceId::new(detail.id.clone())?,
                ),
            );
            let receipt = ReviewAdmissionReceipt::new(
                prepared.admission_key.clone(),
                prepared.descriptor_root.clone(),
                prepared.payload_root.clone(),
                prepared.canonical_review_root.clone(),
                commit_projection_root(&detail, Limits::default())?,
                capture,
                semantic_commit_timestamp(
                    detail
                        .time
                        .as_deref()
                        .ok_or_else(|| Error::invalid("semantic commit timestamp"))?,
                )?,
                prepared.expected_review_ids.clone(),
            )?;
            receipt.verify_prepared(prepared)?;
            return Ok(ReviewAdmissionRecovery::Exact(Box::new(receipt)));
        }

        // A colliding record without this attempt's marker can never prove
        // completion and must not be overwritten by a retry.
        let expected = prepared
            .expected_review_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if self
            .writer
            .read_reviews(&head)
            .await?
            .iter()
            .any(|record| expected.contains(record.id()))
        {
            return Ok(ReviewAdmissionRecovery::Conflict);
        }
        Ok(ReviewAdmissionRecovery::Absent)
    }

    pub async fn recover_or_admit_review(
        &self,
        prepared: &ReviewBundlePrepared,
        bundle: &ValidatedReviewBundle,
    ) -> Result<ReviewAdmissionReceipt> {
        prepared.verify_bundle(bundle)?;
        match self.recover_review(prepared).await? {
            ReviewAdmissionRecovery::Exact(receipt) => Ok(*receipt),
            ReviewAdmissionRecovery::Absent => self.admit_review_once(bundle).await,
            ReviewAdmissionRecovery::Conflict => Err(Error::new(
                ErrorKind::Conflict,
                "review admission recovery conflict",
            )),
        }
    }

    async fn admit_review_once(
        &self,
        bundle: &ValidatedReviewBundle,
    ) -> Result<ReviewAdmissionReceipt> {
        self.writer
            .verify_capture(bundle.validation_capture())
            .await?;
        let transaction = review_transaction(
            bundle,
            self.writer.options.review_graph.as_str(),
            self.writer.options.review_codec_limits,
        )?;
        let before = self
            .writer
            .writer
            .ledger(self.writer.options.reader.ledger.as_str())
            .await
            .map_err(map_backend)?;
        let expected_t = bundle
            .validation_capture()
            .pin()
            .revision()
            .as_str()
            .parse::<i64>()
            .map_err(|_| Error::invalid("semantic transaction"))?;
        if before.t() != expected_t
            || before
                .head_commit_id
                .as_ref()
                .map(ToString::to_string)
                .as_deref()
                != Some(bundle.validation_capture().pin().receipt().as_str())
        {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "review admission head changed before commit",
            ));
        }
        let committed = self
            .writer
            .writer
            .insert(before, &transaction)
            .await
            .map_err(map_backend)?
            .ledger;
        let detail = self
            .writer
            .writer
            .graph(self.writer.options.reader.ledger.as_str())
            .commit_t(committed.t())
            .execute()
            .await
            .map_err(map_backend)?;
        let observed = decode_commit_reviews(
            &detail,
            self.writer.options.review_graph.as_str(),
            self.writer.options.review_codec_limits,
        )?;
        let decoded_review_root = canonical_review_root(&observed, Limits::default())?;
        if observed.len() != bundle.records().len()
            || decoded_review_root != *bundle.canonical_review_root()
        {
            return Err(Error::new(
                ErrorKind::Backend,
                "review admission readback mismatch",
            ));
        }
        let capture = self.writer.reader.capture_current(None).await?;
        if capture.t()
            != u64::try_from(committed.t()).map_err(|_| Error::invalid("semantic transaction"))?
            || capture.commit_cid().as_str() != detail.id
        {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "semantic_snapshot_divergence",
            ));
        }
        ReviewAdmissionReceipt::new(
            bundle.admission_key().clone(),
            bundle.descriptor_root().clone(),
            bundle.payload_root().clone(),
            decoded_review_root,
            commit_projection_root(&detail, Limits::default())?,
            capture.snapshot().clone(),
            semantic_commit_timestamp(
                detail
                    .time
                    .as_deref()
                    .ok_or_else(|| Error::invalid("semantic commit timestamp"))?,
            )?,
            bundle.expected_review_ids(),
        )
    }

    pub async fn recover_business(&self, prepared: &BundlePrepared) -> Result<AdmissionRecovery> {
        self.writer.recover_prepared(prepared).await
    }

    pub async fn recover_or_admit_business(
        &self,
        prepared: &BundlePrepared,
        bundle: &ValidatedSemanticBundle,
    ) -> Result<SemanticAdmissionReceipt> {
        match self.writer.recover_prepared(prepared).await? {
            AdmissionRecovery::Exact(receipt) => Ok(*receipt),
            AdmissionRecovery::Absent => self.writer.admit_once(prepared, bundle).await,
            AdmissionRecovery::Conflict => Err(Error::new(
                ErrorKind::Conflict,
                "semantic admission recovery conflict",
            )),
        }
    }

    /// Exact graph-backed recovery/admission under this session's existing
    /// sole-writer fence. Authorization is repeated immediately before the
    /// recovery decision so stale-absent successor admission cannot lose its
    /// retained dependency set.
    pub async fn recover_or_admit_business_with_disclosure(
        &self,
        principal: &str,
        action: &str,
        policy_basis: &SemanticPolicyBasis,
        supports: &BTreeSet<String>,
        prepared: &BundlePrepared,
        bundle: &ValidatedSemanticBundle,
    ) -> Result<SemanticAdmissionReceipt> {
        self.authorize_disclosure(principal, action, policy_basis, supports)
            .await?;
        self.recover_or_admit_business(prepared, bundle).await
    }
}

impl SemanticBundleWriter for FlureeSemanticWriter {
    fn preflight<'a>(&'a self, bundle: &'a ValidatedSemanticBundle) -> IoFuture<'a, ()> {
        Box::pin(async move {
            self.verify_validation_capture(bundle).await?;
            encode_bundle(
                bundle.claims(),
                self.options.claims_graph.as_str(),
                self.options.codec_limits,
            )?;
            Ok(())
        })
    }

    fn recover<'a>(&'a self, prepared: &'a BundlePrepared) -> IoFuture<'a, AdmissionRecovery> {
        Box::pin(async move {
            let _guard = self.serial.lock().await;
            self.recover_prepared(prepared).await
        })
    }

    fn recover_or_admit<'a>(
        &'a self,
        prepared: &'a BundlePrepared,
        bundle: &'a ValidatedSemanticBundle,
    ) -> IoFuture<'a, SemanticAdmissionReceipt> {
        Box::pin(async move {
            let _guard = self.serial.lock().await;
            match self.recover_prepared(prepared).await? {
                AdmissionRecovery::Exact(receipt) => Ok(*receipt),
                AdmissionRecovery::Absent => self.admit_once(prepared, bundle).await,
                AdmissionRecovery::Conflict => Err(Error::new(
                    ErrorKind::Conflict,
                    "semantic admission recovery conflict",
                )),
            }
        })
    }
}

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const REVIEW_NS: &str = "https://ctxql.example/acquisition-review/v1/";
const ADMISSION_COMMIT_MARKER: &str = "https://ctxql.example/acquisition-review/v1/AdmissionCommit";
const V2_BUSINESS_DESCRIPTOR: &str = "ctxql-extraction-admission-descriptor/v2";

enum MarkerMatch {
    None,
    Exact,
    AttemptConflict,
}

fn business_transaction(
    prepared: &BundlePrepared,
    bundle: &ValidatedSemanticBundle,
    claims_graph: &str,
    review_graph: &str,
    limits: SemanticCodecLimits,
) -> Result<serde_json::Value> {
    let mut transaction = encode_bundle(bundle.claims(), claims_graph, limits)?;
    let projection = bundle.projection();
    let descriptor = projection.field("descriptor")?;
    if descriptor.field("schema")?.as_str()? != V2_BUSINESS_DESCRIPTOR {
        return Ok(transaction);
    }
    if prepared.bundle_id != *bundle.id()
        || prepared.admission_key != bundle.admission_key().as_str()
        || prepared.descriptor_root != *bundle.descriptor_root()
        || prepared.payload_root != *bundle.payload_root()
        || prepared.canonical_claim_root != *bundle.canonical_claim_root()
        || prepared.expected_claim_ids != bundle.expected_claim_ids()
        || prepared.validation_capture != *bundle.validation_capture()
    {
        return Err(Error::new(
            ErrorKind::Conflict,
            "semantic prepared bundle mismatch",
        ));
    }
    let nodes = transaction
        .get_mut("@graph")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| Error::invalid("semantic JSON-LD"))?;
    nodes.push(serde_json::json!({
        "@id": admission_marker_id(&prepared.admission_key),
        "@graph": review_graph,
        "@type": ADMISSION_COMMIT_MARKER,
        format!("{REVIEW_NS}admissionKey"): {"@value": prepared.admission_key},
        format!("{REVIEW_NS}attemptId"): {"@value": prepared.attempt_id.as_str()},
        format!("{REVIEW_NS}descriptorRoot"): {"@value": prepared.descriptor_root.as_str()},
        format!("{REVIEW_NS}payloadRoot"): {"@value": prepared.payload_root.as_str()},
        format!("{REVIEW_NS}logicalBundleKey"): {"@value": prepared.job_id.as_str()},
    }));
    Ok(transaction)
}

fn review_transaction(
    bundle: &ValidatedReviewBundle,
    graph: &str,
    limits: ReviewCodecLimits,
) -> Result<serde_json::Value> {
    let mut transaction = encode_review_bundle(bundle.records(), graph, limits)?;
    let nodes = transaction
        .get_mut("@graph")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| Error::invalid("review JSON-LD"))?;
    nodes.push(serde_json::json!({
        "@id": admission_marker_id(bundle.admission_key().as_str()),
        "@graph": graph,
        "@type": ADMISSION_COMMIT_MARKER,
        format!("{REVIEW_NS}admissionKey"): {"@value": bundle.admission_key().as_str()},
        format!("{REVIEW_NS}attemptId"): {"@value": bundle.attempt_id().as_str()},
        format!("{REVIEW_NS}descriptorRoot"): {"@value": bundle.descriptor_root().as_str()},
        format!("{REVIEW_NS}payloadRoot"): {"@value": bundle.payload_root().as_str()},
        format!("{REVIEW_NS}logicalBundleKey"): {"@value": bundle.logical_bundle_key()},
    }));
    if serde_json::to_vec(&transaction)
        .map_err(|_| Error::invalid("review JSON-LD"))?
        .len()
        > limits.max_bytes
    {
        return Err(Error::limit());
    }
    Ok(transaction)
}

fn business_marker_match(
    detail: &fluree_db_api::CommitDetail,
    prepared: &BundlePrepared,
    graph: &str,
) -> Result<MarkerMatch> {
    marker_match_fields(
        detail,
        graph,
        &prepared.admission_key,
        prepared.attempt_id.as_str(),
        prepared.descriptor_root.as_str(),
        prepared.payload_root.as_str(),
        prepared.job_id.as_str(),
    )
}

fn marker_match(
    detail: &fluree_db_api::CommitDetail,
    prepared: &ReviewBundlePrepared,
    graph: &str,
) -> Result<MarkerMatch> {
    marker_match_fields(
        detail,
        graph,
        prepared.admission_key.as_str(),
        prepared.attempt_id.as_str(),
        prepared.descriptor_root.as_str(),
        prepared.payload_root.as_str(),
        &prepared.logical_bundle_key,
    )
}

#[allow(clippy::too_many_arguments)]
fn marker_match_fields(
    detail: &fluree_db_api::CommitDetail,
    graph: &str,
    admission_key: &str,
    attempt_id: &str,
    descriptor_root: &str,
    payload_root: &str,
    logical_bundle_key: &str,
) -> Result<MarkerMatch> {
    let mut subjects = std::collections::BTreeSet::new();
    for flake in &detail.flakes {
        if flake.op
            && flake
                .graph
                .as_deref()
                .is_some_and(|value| expand_commit_iri(value, detail) == graph)
            && is_rdf_type(&flake.p)
            && flake.dt == "@id"
            && resolved_string(&flake.o) == Some(ADMISSION_COMMIT_MARKER)
        {
            subjects.insert(flake.s.as_str());
        }
    }
    let mut outcome = MarkerMatch::None;
    for subject in subjects {
        let mut values = std::collections::BTreeMap::<String, Vec<&str>>::new();
        for flake in detail.flakes.iter().filter(|flake| {
            flake.op
                && flake
                    .graph
                    .as_deref()
                    .is_some_and(|value| expand_commit_iri(value, detail) == graph)
                && flake.s == subject
        }) {
            let predicate = expand_commit_iri(&flake.p, detail);
            if let (Some(local), Some(value)) =
                (predicate.strip_prefix(REVIEW_NS), resolved_string(&flake.o))
            {
                values.entry(local.to_owned()).or_default().push(value);
            }
        }
        let one = |name: &str| {
            values
                .get(name)
                .filter(|items| items.len() == 1)
                .map(|items| items[0])
        };
        let attempt = one("attemptId");
        let key = one("admissionKey");
        // Admission keys (and their marker subjects) identify one concrete
        // bundle. Review and dependent business bundles intentionally share
        // an attempt/logical key, so attempt identity alone is not relevance.
        if expand_commit_iri(subject, detail) == admission_marker_id(admission_key)
            || key == Some(admission_key)
        {
            let exact = attempt == Some(attempt_id)
                && key == Some(admission_key)
                && one("descriptorRoot") == Some(descriptor_root)
                && one("payloadRoot") == Some(payload_root)
                && one("logicalBundleKey") == Some(logical_bundle_key);
            if !exact {
                return Ok(MarkerMatch::AttemptConflict);
            }
            if matches!(outcome, MarkerMatch::Exact) {
                return Ok(MarkerMatch::AttemptConflict);
            }
            outcome = MarkerMatch::Exact;
        }
    }
    Ok(outcome)
}

fn commit_claim_ids(
    detail: &fluree_db_api::CommitDetail,
    graph: &str,
) -> std::collections::BTreeSet<String> {
    detail
        .flakes
        .iter()
        .filter(|flake| {
            flake.op
                && flake
                    .graph
                    .as_deref()
                    .is_some_and(|value| expand_commit_iri(value, detail) == graph)
                && flake.p.ends_with("reifiesSubject")
        })
        .map(|flake| expand_commit_iri(&flake.s, detail))
        .collect()
}

fn decode_commit_claims(
    detail: &fluree_db_api::CommitDetail,
    graph: &str,
    limits: SemanticCodecLimits,
) -> Result<Vec<CandidateClaim>> {
    let marker = format!("{NS}Claim");
    let subjects = detail
        .flakes
        .iter()
        .filter(|flake| {
            flake.op
                && flake
                    .graph
                    .as_deref()
                    .is_some_and(|value| expand_commit_iri(value, detail) == graph)
                && is_rdf_type(&flake.p)
                && flake.dt == "@id"
                && resolved_string(&flake.o) == Some(marker.as_str())
        })
        .map(|flake| flake.s.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let transaction_time = semantic_commit_timestamp(
        detail
            .time
            .as_deref()
            .ok_or_else(|| Error::invalid("semantic commit timestamp"))?,
    )?;
    subjects
        .into_iter()
        .map(|subject| {
            let flakes = detail.flakes.iter().filter(|flake| {
                flake.op
                    && flake.s == subject
                    && flake
                        .graph
                        .as_deref()
                        .is_some_and(|value| expand_commit_iri(value, detail) == graph)
            });
            let mut reified_subject = Vec::new();
            let mut reified_predicate = Vec::new();
            let mut reified_object = Vec::new();
            let mut metadata = Vec::new();
            for flake in flakes {
                let predicate = expand_commit_iri(&flake.p, detail);
                if predicate.ends_with("reifiesSubject") {
                    reified_subject.push(commit_claim_iri(flake, detail)?);
                } else if predicate.ends_with("reifiesPredicate") {
                    reified_predicate.push(commit_claim_iri(flake, detail)?);
                } else if predicate.ends_with("reifiesObject") {
                    reified_object.push(commit_claim_term(flake, detail)?);
                } else if predicate.ends_with("reifiesGraph") {
                    if commit_claim_iri(flake, detail)? != graph {
                        return Err(Error::invalid("semantic commit claim graph"));
                    }
                } else {
                    metadata.push(MetadataFact {
                        graph: graph.to_owned(),
                        predicate,
                        object: commit_claim_term(flake, detail)?,
                    });
                }
            }
            if reified_subject.len() != 1
                || reified_predicate.len() != 1
                || reified_object.len() != 1
            {
                return Err(Error::invalid("semantic commit claim shape"));
            }
            let document = RdfClaimDocument {
                graph: graph.to_owned(),
                claim_iri: expand_commit_iri(&subject, detail),
                subject_iri: reified_subject.pop().unwrap(),
                predicate_iri: reified_predicate.pop().unwrap(),
                object: reified_object.pop().unwrap(),
                metadata,
                attachment_transaction_time: transaction_time,
            };
            match decode_claim(&document, limits)? {
                ExportRecord::Claim(claim) => Ok(claim.candidate().clone()),
                ExportRecord::Lifecycle { assertion, .. } => Ok(assertion.candidate().clone()),
                ExportRecord::Resource(_) | ExportRecord::Artifact(_) => {
                    Err(Error::invalid("semantic commit claim record"))
                }
            }
        })
        .collect()
}

fn commit_claim_iri(
    flake: &fluree_db_api::ResolvedFlake,
    detail: &fluree_db_api::CommitDetail,
) -> Result<String> {
    if flake.dt != "@id" {
        return Err(Error::invalid("semantic commit IRI"));
    }
    resolved_string(&flake.o)
        .map(|value| expand_commit_iri(value, detail))
        .ok_or_else(|| Error::invalid("semantic commit IRI"))
}

fn commit_claim_term(
    flake: &fluree_db_api::ResolvedFlake,
    detail: &fluree_db_api::CommitDetail,
) -> Result<ExactRdfTerm> {
    if flake.dt == "@id" {
        let lexical =
            resolved_string(&flake.o).ok_or_else(|| Error::invalid("semantic commit term"))?;
        return Ok(ExactRdfTerm::Iri(expand_commit_iri(lexical, detail)));
    }
    let mut lexical = match &flake.o {
        ResolvedValue::String(value) | ResolvedValue::Lexical(value) => value.clone(),
        ResolvedValue::Boolean(value) => value.to_string(),
        ResolvedValue::Long(value) => value.to_string(),
        ResolvedValue::Double(value) => value.to_string(),
    };
    let datatype = expand_commit_iri(&flake.dt, detail);
    if datatype == "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON" {
        lexical = lexical
            .strip_prefix("@json:")
            .ok_or_else(|| Error::invalid("semantic commit JSON term"))?
            .to_owned();
    }
    Ok(ExactRdfTerm::Literal {
        lexical,
        datatype,
        language: flake.lang.clone(),
    })
}

fn business_receipt(
    prepared: &BundlePrepared,
    detail: &fluree_db_api::CommitDetail,
    options: &SemanticWriterOptions,
) -> Result<SemanticAdmissionReceipt> {
    let capture = SnapshotRef::new(
        options.reader.backend.clone(),
        GraphPin::new(
            options.reader.authority.clone(),
            options.reader.ledger.clone(),
            VersionId::new(detail.t.to_string())?,
            ResourceId::new(detail.id.clone())?,
        ),
    );
    SemanticAdmissionReceipt::new(
        cdb_core::id::IdempotencyKey::new(&prepared.admission_key)?,
        prepared.descriptor_root.clone(),
        prepared.payload_root.clone(),
        prepared.canonical_claim_root.clone(),
        commit_projection_root(detail, Limits::default())?,
        capture,
        semantic_commit_timestamp(
            detail
                .time
                .as_deref()
                .ok_or_else(|| Error::invalid("semantic commit timestamp"))?,
        )?,
        prepared.expected_claim_ids.clone(),
    )
}

fn decode_commit_reviews(
    detail: &fluree_db_api::CommitDetail,
    graph: &str,
    limits: ReviewCodecLimits,
) -> Result<Vec<cdb_core::review::ReviewRecord>> {
    let record_subjects = detail
        .flakes
        .iter()
        .filter(|flake| {
            flake.op
                && flake
                    .graph
                    .as_deref()
                    .is_some_and(|value| expand_commit_iri(value, detail) == graph)
                && is_rdf_type(&flake.p)
                && flake.dt == "@id"
                && resolved_string(&flake.o) == Some(RECORD_MARKER)
        })
        .map(|flake| flake.s.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut documents =
        std::collections::BTreeMap::<String, Vec<crate::review_codec::ReviewFact>>::new();
    for flake in &detail.flakes {
        if !flake.op
            || flake
                .graph
                .as_deref()
                .is_none_or(|value| expand_commit_iri(value, detail) != graph)
            || !record_subjects.contains(&flake.s)
        {
            continue;
        }
        documents
            .entry(flake.s.clone())
            .or_default()
            .push(crate::review_codec::ReviewFact {
                graph: graph.to_owned(),
                predicate: expand_commit_iri(&flake.p, detail),
                object: commit_review_term(flake, detail)?,
            });
    }
    documents
        .into_iter()
        .map(|(review_iri, facts)| {
            decode_review(
                &RdfReviewDocument {
                    graph: graph.to_owned(),
                    review_iri: expand_commit_iri(&review_iri, detail),
                    facts,
                },
                limits,
            )
        })
        .collect()
}

fn commit_review_term(
    flake: &fluree_db_api::ResolvedFlake,
    detail: &fluree_db_api::CommitDetail,
) -> Result<ExactReviewTerm> {
    let lexical = resolved_string(&flake.o).ok_or_else(|| Error::invalid("review commit term"))?;
    if flake.dt == "@id" {
        Ok(ExactReviewTerm::Iri(expand_commit_iri(lexical, detail)))
    } else {
        Ok(ExactReviewTerm::Literal {
            lexical: lexical.to_owned(),
            datatype: expand_commit_iri(&flake.dt, detail),
            language: flake.lang.clone(),
        })
    }
}

fn admission_marker_id(admission_key: &str) -> String {
    format!(
        "urn:ctxql:admission-commit:{}",
        &ContentHash::of_bytes(admission_key.as_bytes()).as_str()[7..]
    )
}

fn is_rdf_type(value: &str) -> bool {
    value == RDF_TYPE || value == "rdf:type"
}

fn expand_commit_iri(value: &str, detail: &fluree_db_api::CommitDetail) -> String {
    let Some((prefix, suffix)) = value.split_once(':') else {
        return value.to_owned();
    };
    detail
        .context
        .get(prefix)
        .map(|namespace| format!("{namespace}{suffix}"))
        .unwrap_or_else(|| value.to_owned())
}

fn resolved_string(value: &ResolvedValue) -> Option<&str> {
    match value {
        ResolvedValue::String(value) | ResolvedValue::Lexical(value) => Some(value),
        ResolvedValue::Boolean(_) | ResolvedValue::Long(_) | ResolvedValue::Double(_) => None,
    }
}

fn decode_readback_row(
    row: &serde_json::Value,
    graph: &str,
    limits: SemanticCodecLimits,
) -> Result<CandidateClaim> {
    const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
    const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
    let claim = bound(row, "claim")?;
    let mut metadata = vec![
        MetadataFact {
            graph: graph.into(),
            predicate: RDF_TYPE.into(),
            object: ExactRdfTerm::Iri(format!("{NS}Claim")),
        },
        iri_metadata(row, graph, "relationType")?,
        iri_metadata(row, graph, "subjectType")?,
        iri_metadata(row, graph, "objectType")?,
        iri_metadata(row, graph, "claimType")?,
        MetadataFact {
            graph: graph.into(),
            predicate: format!("{NS}confidence"),
            object: ExactRdfTerm::Literal {
                lexical: bound(row, "confidence")?,
                datatype: format!("{XSD}decimal"),
                language: None,
            },
        },
        iri_metadata(row, graph, "grounding")?,
        json_metadata(row, graph, "lineage")?,
        json_metadata(row, graph, "extensions")?,
    ];
    for (binding, predicate) in [
        ("validTime", "validTime"),
        ("sourceObservedAt", "sourceObservedAt"),
    ] {
        if row.get(binding).is_some() {
            metadata.push(MetadataFact {
                graph: graph.into(),
                predicate: format!("{NS}{predicate}"),
                object: ExactRdfTerm::Literal {
                    lexical: bound(row, binding)?,
                    datatype: format!("{XSD}dateTime"),
                    language: None,
                },
            });
        }
    }
    let document = RdfClaimDocument {
        graph: graph.into(),
        claim_iri: claim,
        subject_iri: bound(row, "s")?,
        predicate_iri: bound(row, "p")?,
        object: bound_term(row, "o")?,
        metadata,
        // Candidate decoding does not use attachment time; the receipt binds
        // the exact native commit timestamp separately below.
        attachment_transaction_time: cdb_core::Timestamp::parse("1970-01-01T00:00:00.000Z")?,
    };
    match decode_claim(&document, limits)? {
        ExportRecord::Claim(claim) => Ok(claim.candidate().clone()),
        ExportRecord::Lifecycle { assertion, .. } => Ok(assertion.candidate().clone()),
        ExportRecord::Resource(_) | ExportRecord::Artifact(_) => {
            Err(Error::invalid("semantic admission readback record"))
        }
    }
}

fn iri_metadata(row: &serde_json::Value, graph: &str, binding: &str) -> Result<MetadataFact> {
    let predicate = if binding == "grounding" {
        "groundingLevel"
    } else {
        binding
    };
    Ok(MetadataFact {
        graph: graph.into(),
        predicate: format!("{NS}{predicate}"),
        object: ExactRdfTerm::Iri(bound(row, binding)?),
    })
}

fn json_metadata(row: &serde_json::Value, graph: &str, binding: &str) -> Result<MetadataFact> {
    const RDF_JSON: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON";
    Ok(MetadataFact {
        graph: graph.into(),
        predicate: format!("{NS}{binding}"),
        object: ExactRdfTerm::Literal {
            lexical: bound(row, binding)?,
            datatype: RDF_JSON.into(),
            language: None,
        },
    })
}

fn bound(row: &serde_json::Value, name: &str) -> Result<String> {
    row.get(name)
        .and_then(|value| value.get("value"))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| Error::new(ErrorKind::Backend, "semantic admission readback binding"))
}

fn review_bound_term(row: &serde_json::Value, name: &str) -> Result<ExactReviewTerm> {
    let value = row
        .get(name)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| Error::new(ErrorKind::Backend, "review admission readback term"))?;
    let lexical = value
        .get("value")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::new(ErrorKind::Backend, "review admission readback term"))?;
    if value.get("type").and_then(serde_json::Value::as_str) == Some("uri") {
        return Ok(ExactReviewTerm::Iri(lexical.into()));
    }
    Ok(ExactReviewTerm::Literal {
        lexical: lexical.into(),
        datatype: value
            .get("datatype")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("http://www.w3.org/2001/XMLSchema#string")
            .into(),
        language: value
            .get("xml:lang")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
    })
}

fn bound_term(row: &serde_json::Value, name: &str) -> Result<ExactRdfTerm> {
    let value = row
        .get(name)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| Error::new(ErrorKind::Backend, "semantic admission readback term"))?;
    let lexical = value
        .get("value")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::new(ErrorKind::Backend, "semantic admission readback term"))?;
    if value.get("type").and_then(serde_json::Value::as_str) == Some("uri") {
        return Ok(ExactRdfTerm::Iri(lexical.into()));
    }
    let datatype = value
        .get("datatype")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("http://www.w3.org/2001/XMLSchema#string");
    Ok(ExactRdfTerm::Literal {
        lexical: lexical.into(),
        datatype: datatype.into(),
        language: value
            .get("xml:lang")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
    })
}

fn commit_projection_root(
    detail: &fluree_db_api::CommitDetail,
    limits: Limits,
) -> Result<ContentHash> {
    let mut flakes = detail
        .flakes
        .iter()
        .map(|flake| {
            let object = match &flake.o {
                ResolvedValue::String(value) => V::object([
                    ("kind".into(), V::string("string")),
                    ("value".into(), V::string(value)),
                ])?,
                ResolvedValue::Lexical(value) => V::object([
                    ("kind".into(), V::string("lexical")),
                    ("value".into(), V::string(value)),
                ])?,
                ResolvedValue::Boolean(value) => V::object([
                    ("kind".into(), V::string("boolean")),
                    ("value".into(), V::Bool(*value)),
                ])?,
                ResolvedValue::Long(value) => V::object([
                    ("kind".into(), V::string("long")),
                    ("value".into(), V::string(value.to_string())),
                ])?,
                ResolvedValue::Double(value) => V::object([
                    ("kind".into(), V::string("double-bits")),
                    (
                        "value".into(),
                        V::string(format!("{:016x}", value.to_bits())),
                    ),
                ])?,
            };
            V::object([
                ("subject".into(), V::string(&flake.s)),
                ("predicate".into(), V::string(&flake.p)),
                ("object".into(), object),
                ("datatype".into(), V::string(&flake.dt)),
                (
                    "language".into(),
                    flake.lang.as_ref().map(V::string).unwrap_or(V::Null),
                ),
                (
                    "graph".into(),
                    flake.graph.as_ref().map(V::string).unwrap_or(V::Null),
                ),
                ("op".into(), V::Bool(flake.op)),
            ])
        })
        .collect::<Result<Vec<_>>>()?;
    flakes.sort_by(|left, right| {
        left.canonical_bytes(limits)
            .expect("bounded resolved flake")
            .cmp(
                &right
                    .canonical_bytes(limits)
                    .expect("bounded resolved flake"),
            )
    });
    let projection = V::object([
        (
            "schema".into(),
            V::string("ctxql-fluree-stored-projection/v1"),
        ),
        ("t".into(), V::string(detail.t.to_string())),
        ("cid".into(), V::string(&detail.id)),
        ("flakes".into(), V::Array(flakes)),
    ])?;
    Ok(ContentHash::of_bytes(&projection.canonical_bytes(limits)?))
}

fn map_backend(error: fluree_db_api::ApiError) -> Error {
    Error::new(ErrorKind::Backend, error.to_string())
}
