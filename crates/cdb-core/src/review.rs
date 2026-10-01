//! Closed durable-review records and admission commitments.
//!
//! Review records describe extraction proposals. They are deliberately not
//! semantic claims: suggested predicates and classes remain strings here.

use crate::id::{AttemptId, BundleId, ClaimId, ContentHash, IdempotencyKey, JobId};
use crate::snapshot::{GraphPin, SnapshotRef};
use crate::{CanonicalValue as V, Error, Limits, Result, Timestamp};
use std::collections::BTreeSet;

fn obj(fields: impl IntoIterator<Item = (&'static str, V)>) -> V {
    V::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn identifier(value: impl Into<String>, label: &'static str) -> Result<String> {
    let value = value.into();
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(Error::invalid(label));
    }
    Ok(value)
}

fn strings(value: &V, label: &'static str) -> Result<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| identifier(item.as_str()?, label))
        .collect()
}

fn unique<T: Ord>(values: &[T]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ReviewRecordId(String);
impl ReviewRecordId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        Ok(Self(identifier(value, "nonempty review record ID")?))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VocabularyVerdict {
    Valid,
    Repaired,
    Rejected,
    NotChecked,
}
impl VocabularyVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Repaired => "repaired",
            Self::Rejected => "rejected",
            Self::NotChecked => "not_checked",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "valid" => Ok(Self::Valid),
            "repaired" => Ok(Self::Repaired),
            "rejected" => Ok(Self::Rejected),
            "not_checked" => Ok(Self::NotChecked),
            _ => Err(Error::invalid("review vocabulary verdict")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewAssertionIntent {
    None,
    Direct,
    Provisional,
}
impl ReviewAssertionIntent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Direct => "direct",
            Self::Provisional => "provisional",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "none" => Ok(Self::None),
            "direct" => Ok(Self::Direct),
            "provisional" => Ok(Self::Provisional),
            _ => Err(Error::invalid("review assertion intent")),
        }
    }
}

/// Bounded, inspectable review metadata. Complete proposal/outcome JSON lives
/// in the immutable artifact identified by `artifact_root`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewRecord {
    id: ReviewRecordId,
    component_ref: String,
    source_ref: String,
    artifact_root: ContentHash,
    vocabulary_verdict: VocabularyVerdict,
    assertion_intent: ReviewAssertionIntent,
    reason_codes: Vec<String>,
    suggested_predicates: Vec<String>,
    suggested_types: Vec<String>,
    resolved_predicates: Vec<String>,
    resolved_types: Vec<String>,
    accepted_claim_ids: Vec<ClaimId>,
}

impl ReviewRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ReviewRecordId,
        component_ref: impl Into<String>,
        source_ref: impl Into<String>,
        artifact_root: ContentHash,
        vocabulary_verdict: VocabularyVerdict,
        assertion_intent: ReviewAssertionIntent,
        reason_codes: Vec<String>,
        suggested_predicates: Vec<String>,
        suggested_types: Vec<String>,
        resolved_predicates: Vec<String>,
        resolved_types: Vec<String>,
        accepted_claim_ids: Vec<ClaimId>,
    ) -> Result<Self> {
        let value = Self {
            id,
            component_ref: identifier(component_ref, "review component reference")?,
            source_ref: identifier(source_ref, "review source reference")?,
            artifact_root,
            vocabulary_verdict,
            assertion_intent,
            reason_codes,
            suggested_predicates,
            suggested_types,
            resolved_predicates,
            resolved_types,
            accepted_claim_ids,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        for (values, maximum, label) in [
            (&self.reason_codes, 32, "review reason codes"),
            (&self.suggested_predicates, 8, "suggested predicates"),
            (&self.suggested_types, 8, "suggested types"),
            (&self.resolved_predicates, 32, "resolved predicates"),
            (&self.resolved_types, 32, "resolved types"),
        ] {
            if values.len() > maximum || !unique(values) {
                return Err(Error::invalid(label));
            }
            for value in values {
                identifier(value, label)?;
            }
        }
        if self.accepted_claim_ids.len() > 32 || !unique(&self.accepted_claim_ids) {
            return Err(Error::invalid("review accepted claim links"));
        }
        // Resolved terms are host-verified IRIs. Suggested terms intentionally
        // are not parsed as IRIs.
        for value in self.resolved_predicates.iter().chain(&self.resolved_types) {
            crate::id::Iri::new(value)?;
        }
        Ok(())
    }

    pub fn from_value(value: &V) -> Result<Self> {
        value.closed(
            &[
                "schema",
                "review_id",
                "component_ref",
                "source_ref",
                "artifact_root",
                "vocabulary_verdict",
                "assertion_intent",
                "reason_codes",
                "suggested_predicates",
                "suggested_types",
                "resolved_predicates",
                "resolved_types",
                "accepted_claim_ids",
            ],
            &[],
        )?;
        if value.field("schema")?.as_str()? != "ctxql-acquisition-review-record/v1" {
            return Err(Error::invalid("review record schema"));
        }
        Self::new(
            ReviewRecordId::new(value.field("review_id")?.as_str()?)?,
            value.field("component_ref")?.as_str()?,
            value.field("source_ref")?.as_str()?,
            ContentHash::parse(value.field("artifact_root")?.as_str()?)?,
            VocabularyVerdict::parse(value.field("vocabulary_verdict")?.as_str()?)?,
            ReviewAssertionIntent::parse(value.field("assertion_intent")?.as_str()?)?,
            strings(value.field("reason_codes")?, "review reason code")?,
            strings(value.field("suggested_predicates")?, "suggested predicate")?,
            strings(value.field("suggested_types")?, "suggested type")?,
            strings(value.field("resolved_predicates")?, "resolved predicate")?,
            strings(value.field("resolved_types")?, "resolved type")?,
            value
                .field("accepted_claim_ids")?
                .as_array()?
                .iter()
                .map(|id| ClaimId::new(id.as_str()?))
                .collect::<Result<_>>()?,
        )
    }

    pub fn id(&self) -> &ReviewRecordId {
        &self.id
    }
    pub fn component_ref(&self) -> &str {
        &self.component_ref
    }
    pub fn source_ref(&self) -> &str {
        &self.source_ref
    }
    pub fn artifact_root(&self) -> &ContentHash {
        &self.artifact_root
    }
    pub fn vocabulary_verdict(&self) -> VocabularyVerdict {
        self.vocabulary_verdict
    }
    pub fn assertion_intent(&self) -> ReviewAssertionIntent {
        self.assertion_intent
    }
    pub fn reason_codes(&self) -> &[String] {
        &self.reason_codes
    }
    pub fn suggested_predicates(&self) -> &[String] {
        &self.suggested_predicates
    }
    pub fn suggested_types(&self) -> &[String] {
        &self.suggested_types
    }
    pub fn resolved_predicates(&self) -> &[String] {
        &self.resolved_predicates
    }
    pub fn resolved_types(&self) -> &[String] {
        &self.resolved_types
    }
    pub fn accepted_claim_ids(&self) -> &[ClaimId] {
        &self.accepted_claim_ids
    }

    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql-acquisition-review-record/v1")),
            ("review_id", V::string(self.id.as_str())),
            ("component_ref", V::string(&self.component_ref)),
            ("source_ref", V::string(&self.source_ref)),
            ("artifact_root", V::string(self.artifact_root.as_str())),
            (
                "vocabulary_verdict",
                V::string(self.vocabulary_verdict.as_str()),
            ),
            (
                "assertion_intent",
                V::string(self.assertion_intent.as_str()),
            ),
            (
                "reason_codes",
                V::Array(self.reason_codes.iter().map(V::string).collect()),
            ),
            (
                "suggested_predicates",
                V::Array(self.suggested_predicates.iter().map(V::string).collect()),
            ),
            (
                "suggested_types",
                V::Array(self.suggested_types.iter().map(V::string).collect()),
            ),
            (
                "resolved_predicates",
                V::Array(self.resolved_predicates.iter().map(V::string).collect()),
            ),
            (
                "resolved_types",
                V::Array(self.resolved_types.iter().map(V::string).collect()),
            ),
            (
                "accepted_claim_ids",
                V::Array(
                    self.accepted_claim_ids
                        .iter()
                        .map(|id| V::string(id.as_str()))
                        .collect(),
                ),
            ),
        ])
    }
}

pub fn canonical_review_root(records: &[ReviewRecord], limits: Limits) -> Result<ContentHash> {
    let mut records = records.iter().collect::<Vec<_>>();
    records.sort_by(|a, b| a.id().cmp(b.id()));
    let value = V::Array(records.into_iter().map(ReviewRecord::projection).collect());
    Ok(ContentHash::of_bytes(&value.canonical_bytes(limits)?))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedReviewBundle {
    id: BundleId,
    evaluation_id: String,
    logical_bundle_key: String,
    attempt_id: AttemptId,
    validation_capture: SnapshotRef,
    records: Vec<ReviewRecord>,
    descriptor_root: ContentHash,
    payload_root: ContentHash,
    canonical_review_root: ContentHash,
    admission_key: IdempotencyKey,
}
impl ValidatedReviewBundle {
    pub fn new(
        id: BundleId,
        evaluation_id: impl Into<String>,
        logical_bundle_key: impl Into<String>,
        attempt_id: AttemptId,
        validation_capture: SnapshotRef,
        records: Vec<ReviewRecord>,
        limits: Limits,
    ) -> Result<Self> {
        let evaluation_id = identifier(evaluation_id, "review evaluation ID")?;
        let logical_bundle_key = identifier(logical_bundle_key, "review logical bundle key")?;
        if records.is_empty() || !unique(&records.iter().map(|r| r.id()).collect::<Vec<_>>()) {
            return Err(Error::invalid("review bundle records"));
        }
        let descriptor = obj([
            ("schema", V::string("ctxql-review-bundle-descriptor/v1")),
            ("bundle_id", V::string(id.as_str())),
            ("evaluation_id", V::string(&evaluation_id)),
            ("logical_bundle_key", V::string(&logical_bundle_key)),
            ("attempt_id", V::string(attempt_id.as_str())),
            (
                "validation_capture",
                snapshot_projection(&validation_capture),
            ),
        ]);
        let descriptor_root = ContentHash::of_bytes(&descriptor.canonical_bytes(limits)?);
        let canonical_review_root = canonical_review_root(&records, limits)?;
        let payload = obj([
            ("schema", V::string("ctxql-review-bundle-payload/v1")),
            ("descriptor_root", V::string(descriptor_root.as_str())),
            (
                "records",
                V::Array(records.iter().map(ReviewRecord::projection).collect()),
            ),
        ]);
        let payload_root = ContentHash::of_bytes(&payload.canonical_bytes(limits)?);
        let admission_root = ContentHash::of_bytes(
            &obj([
                ("schema", V::string("ctxql-review-admission-key/v1")),
                ("descriptor_root", V::string(descriptor_root.as_str())),
                ("payload_root", V::string(payload_root.as_str())),
            ])
            .canonical_bytes(limits)?,
        );
        let admission_key =
            IdempotencyKey::new(format!("review:{}", &admission_root.as_str()[7..]))?;
        Ok(Self {
            id,
            evaluation_id,
            logical_bundle_key,
            attempt_id,
            validation_capture,
            records,
            descriptor_root,
            payload_root,
            canonical_review_root,
            admission_key,
        })
    }

    pub fn from_value(value: &V, limits: Limits) -> Result<Self> {
        value.closed(
            &[
                "schema",
                "bundle_id",
                "evaluation_id",
                "logical_bundle_key",
                "attempt_id",
                "validation_capture",
                "records",
                "descriptor_root",
                "payload_root",
                "canonical_review_root",
                "admission_key",
            ],
            &[],
        )?;
        if value.field("schema")?.as_str()? != "ctxql-validated-review-bundle/v1" {
            return Err(Error::invalid("review bundle schema"));
        }
        let bundle = Self::new(
            BundleId::new(value.field("bundle_id")?.as_str()?)?,
            value.field("evaluation_id")?.as_str()?,
            value.field("logical_bundle_key")?.as_str()?,
            AttemptId::new(value.field("attempt_id")?.as_str()?)?,
            snapshot_from_value(value.field("validation_capture")?)?,
            value
                .field("records")?
                .as_array()?
                .iter()
                .map(ReviewRecord::from_value)
                .collect::<Result<_>>()?,
            limits,
        )?;
        if bundle.descriptor_root.as_str() != value.field("descriptor_root")?.as_str()?
            || bundle.payload_root.as_str() != value.field("payload_root")?.as_str()?
            || bundle.canonical_review_root.as_str()
                != value.field("canonical_review_root")?.as_str()?
            || bundle.admission_key.as_str() != value.field("admission_key")?.as_str()?
        {
            return Err(Error::invalid("review bundle commitment"));
        }
        Ok(bundle)
    }

    pub fn id(&self) -> &BundleId {
        &self.id
    }
    pub fn evaluation_id(&self) -> &str {
        &self.evaluation_id
    }
    pub fn logical_bundle_key(&self) -> &str {
        &self.logical_bundle_key
    }
    pub fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }
    pub fn validation_capture(&self) -> &SnapshotRef {
        &self.validation_capture
    }
    pub fn records(&self) -> &[ReviewRecord] {
        &self.records
    }
    pub fn descriptor_root(&self) -> &ContentHash {
        &self.descriptor_root
    }
    pub fn payload_root(&self) -> &ContentHash {
        &self.payload_root
    }
    pub fn canonical_review_root(&self) -> &ContentHash {
        &self.canonical_review_root
    }
    pub fn admission_key(&self) -> &IdempotencyKey {
        &self.admission_key
    }
    pub fn expected_review_ids(&self) -> Vec<ReviewRecordId> {
        self.records.iter().map(|r| r.id.clone()).collect()
    }

    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql-validated-review-bundle/v1")),
            ("bundle_id", V::string(self.id.as_str())),
            ("evaluation_id", V::string(&self.evaluation_id)),
            ("logical_bundle_key", V::string(&self.logical_bundle_key)),
            ("attempt_id", V::string(self.attempt_id.as_str())),
            (
                "validation_capture",
                snapshot_projection(&self.validation_capture),
            ),
            (
                "records",
                V::Array(self.records.iter().map(ReviewRecord::projection).collect()),
            ),
            ("descriptor_root", V::string(self.descriptor_root.as_str())),
            ("payload_root", V::string(self.payload_root.as_str())),
            (
                "canonical_review_root",
                V::string(self.canonical_review_root.as_str()),
            ),
            ("admission_key", V::string(self.admission_key.as_str())),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewSafeCounts {
    pub records: u64,
    pub reason_codes: u64,
    pub suggested_terms: u64,
    pub resolved_terms: u64,
    pub accepted_claim_links: u64,
}
impl ReviewSafeCounts {
    pub fn for_records(records: &[ReviewRecord]) -> Self {
        Self {
            records: records.len() as u64,
            reason_codes: records.iter().map(|r| r.reason_codes.len() as u64).sum(),
            suggested_terms: records
                .iter()
                .map(|r| (r.suggested_predicates.len() + r.suggested_types.len()) as u64)
                .sum(),
            resolved_terms: records
                .iter()
                .map(|r| (r.resolved_predicates.len() + r.resolved_types.len()) as u64)
                .sum(),
            accepted_claim_links: records
                .iter()
                .map(|r| r.accepted_claim_ids.len() as u64)
                .sum(),
        }
    }
    pub fn from_value(value: &V) -> Result<Self> {
        value.closed(
            &[
                "records",
                "reason_codes",
                "suggested_terms",
                "resolved_terms",
                "accepted_claim_links",
            ],
            &[],
        )?;
        Ok(Self {
            records: value.field("records")?.u64()?,
            reason_codes: value.field("reason_codes")?.u64()?,
            suggested_terms: value.field("suggested_terms")?.u64()?,
            resolved_terms: value.field("resolved_terms")?.u64()?,
            accepted_claim_links: value.field("accepted_claim_links")?.u64()?,
        })
    }
    pub fn projection(&self) -> V {
        obj([
            ("records", V::integer(self.records)),
            ("reason_codes", V::integer(self.reason_codes)),
            ("suggested_terms", V::integer(self.suggested_terms)),
            ("resolved_terms", V::integer(self.resolved_terms)),
            (
                "accepted_claim_links",
                V::integer(self.accepted_claim_links),
            ),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewBundlePrepared {
    pub job_id: JobId,
    pub bundle_id: BundleId,
    pub evaluation_id: String,
    pub logical_bundle_key: String,
    pub attempt_id: AttemptId,
    pub admission_key: IdempotencyKey,
    pub descriptor_root: ContentHash,
    pub payload_root: ContentHash,
    pub canonical_review_root: ContentHash,
    pub expected_review_ids: Vec<ReviewRecordId>,
    pub validation_capture: SnapshotRef,
    pub safe_counts: ReviewSafeCounts,
    pub recorded_at: Timestamp,
}
impl ReviewBundlePrepared {
    pub fn new(job_id: JobId, bundle: &ValidatedReviewBundle, recorded_at: Timestamp) -> Self {
        Self {
            job_id,
            bundle_id: bundle.id.clone(),
            evaluation_id: bundle.evaluation_id.clone(),
            logical_bundle_key: bundle.logical_bundle_key.clone(),
            attempt_id: bundle.attempt_id.clone(),
            admission_key: bundle.admission_key.clone(),
            descriptor_root: bundle.descriptor_root.clone(),
            payload_root: bundle.payload_root.clone(),
            canonical_review_root: bundle.canonical_review_root.clone(),
            expected_review_ids: bundle.expected_review_ids(),
            validation_capture: bundle.validation_capture.clone(),
            safe_counts: ReviewSafeCounts::for_records(&bundle.records),
            recorded_at,
        }
    }
    pub fn from_value(value: &V) -> Result<Self> {
        value.closed(
            &[
                "schema",
                "job_id",
                "bundle_id",
                "evaluation_id",
                "logical_bundle_key",
                "attempt_id",
                "admission_key",
                "descriptor_root",
                "payload_root",
                "canonical_review_root",
                "expected_review_ids",
                "validation_capture",
                "safe_counts",
                "recorded_at",
            ],
            &[],
        )?;
        if value.field("schema")?.as_str()? != "ctxql-review-bundle-prepared/v1" {
            return Err(Error::invalid("prepared review bundle schema"));
        }
        let prepared = Self {
            job_id: JobId::new(value.field("job_id")?.as_str()?)?,
            bundle_id: BundleId::new(value.field("bundle_id")?.as_str()?)?,
            evaluation_id: identifier(
                value.field("evaluation_id")?.as_str()?,
                "review evaluation ID",
            )?,
            logical_bundle_key: identifier(
                value.field("logical_bundle_key")?.as_str()?,
                "review logical bundle key",
            )?,
            attempt_id: AttemptId::new(value.field("attempt_id")?.as_str()?)?,
            admission_key: IdempotencyKey::new(value.field("admission_key")?.as_str()?)?,
            descriptor_root: ContentHash::parse(value.field("descriptor_root")?.as_str()?)?,
            payload_root: ContentHash::parse(value.field("payload_root")?.as_str()?)?,
            canonical_review_root: ContentHash::parse(
                value.field("canonical_review_root")?.as_str()?,
            )?,
            expected_review_ids: value
                .field("expected_review_ids")?
                .as_array()?
                .iter()
                .map(|v| ReviewRecordId::new(v.as_str()?))
                .collect::<Result<_>>()?,
            validation_capture: snapshot_from_value(value.field("validation_capture")?)?,
            safe_counts: ReviewSafeCounts::from_value(value.field("safe_counts")?)?,
            recorded_at: Timestamp::parse(value.field("recorded_at")?.as_str()?)?,
        };
        prepared.validate()?;
        Ok(prepared)
    }

    pub fn validate(&self) -> Result<()> {
        identifier(&self.evaluation_id, "review evaluation ID")?;
        identifier(&self.logical_bundle_key, "review logical bundle key")?;
        if self.expected_review_ids.is_empty()
            || !unique(&self.expected_review_ids)
            || self.safe_counts.records != self.expected_review_ids.len() as u64
        {
            return Err(Error::invalid("prepared review bundle"));
        }
        Ok(())
    }

    /// Verify that an immutable prepared journal record is bound to exactly
    /// the validated payload which a caller proposes to recover or admit.
    pub fn verify_bundle(&self, bundle: &ValidatedReviewBundle) -> Result<()> {
        self.validate()?;
        if self.bundle_id != *bundle.id()
            || self.evaluation_id != bundle.evaluation_id()
            || self.logical_bundle_key != bundle.logical_bundle_key()
            || self.attempt_id != *bundle.attempt_id()
            || self.admission_key != *bundle.admission_key()
            || self.descriptor_root != *bundle.descriptor_root()
            || self.payload_root != *bundle.payload_root()
            || self.canonical_review_root != *bundle.canonical_review_root()
            || self.expected_review_ids != bundle.expected_review_ids()
            || self.validation_capture != *bundle.validation_capture()
            || self.safe_counts != ReviewSafeCounts::for_records(bundle.records())
        {
            return Err(Error::new(
                crate::ErrorKind::Conflict,
                "prepared review bundle binding mismatch",
            ));
        }
        Ok(())
    }

    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql-review-bundle-prepared/v1")),
            ("job_id", V::string(self.job_id.as_str())),
            ("bundle_id", V::string(self.bundle_id.as_str())),
            ("evaluation_id", V::string(&self.evaluation_id)),
            ("logical_bundle_key", V::string(&self.logical_bundle_key)),
            ("attempt_id", V::string(self.attempt_id.as_str())),
            ("admission_key", V::string(self.admission_key.as_str())),
            ("descriptor_root", V::string(self.descriptor_root.as_str())),
            ("payload_root", V::string(self.payload_root.as_str())),
            (
                "canonical_review_root",
                V::string(self.canonical_review_root.as_str()),
            ),
            (
                "expected_review_ids",
                V::Array(
                    self.expected_review_ids
                        .iter()
                        .map(|id| V::string(id.as_str()))
                        .collect(),
                ),
            ),
            (
                "validation_capture",
                snapshot_projection(&self.validation_capture),
            ),
            ("safe_counts", self.safe_counts.projection()),
            ("recorded_at", V::string(self.recorded_at.canonical())),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewAdmissionReceipt {
    admission_key: IdempotencyKey,
    descriptor_root: ContentHash,
    payload_root: ContentHash,
    decoded_review_root: ContentHash,
    stored_projection_root: ContentHash,
    snapshot: SnapshotRef,
    transaction_time: Timestamp,
    review_ids: Vec<ReviewRecordId>,
}
impl ReviewAdmissionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admission_key: IdempotencyKey,
        descriptor_root: ContentHash,
        payload_root: ContentHash,
        decoded_review_root: ContentHash,
        stored_projection_root: ContentHash,
        snapshot: SnapshotRef,
        transaction_time: Timestamp,
        review_ids: Vec<ReviewRecordId>,
    ) -> Result<Self> {
        if review_ids.is_empty() || !unique(&review_ids) {
            return Err(Error::invalid("review admission receipt IDs"));
        }
        Ok(Self {
            admission_key,
            descriptor_root,
            payload_root,
            decoded_review_root,
            stored_projection_root,
            snapshot,
            transaction_time,
            review_ids,
        })
    }
    pub fn from_value(value: &V) -> Result<Self> {
        value.closed(
            &[
                "schema",
                "admission_key",
                "descriptor_root",
                "payload_root",
                "decoded_review_root",
                "stored_projection_root",
                "snapshot",
                "transaction_time",
                "review_ids",
            ],
            &[],
        )?;
        if value.field("schema")?.as_str()? != "ctxql-review-admission-receipt/v1" {
            return Err(Error::invalid("review admission receipt schema"));
        }
        Self::new(
            IdempotencyKey::new(value.field("admission_key")?.as_str()?)?,
            ContentHash::parse(value.field("descriptor_root")?.as_str()?)?,
            ContentHash::parse(value.field("payload_root")?.as_str()?)?,
            ContentHash::parse(value.field("decoded_review_root")?.as_str()?)?,
            ContentHash::parse(value.field("stored_projection_root")?.as_str()?)?,
            snapshot_from_value(value.field("snapshot")?)?,
            Timestamp::parse(value.field("transaction_time")?.as_str()?)?,
            value
                .field("review_ids")?
                .as_array()?
                .iter()
                .map(|v| ReviewRecordId::new(v.as_str()?))
                .collect::<Result<_>>()?,
        )
    }
    pub fn admission_key(&self) -> &IdempotencyKey {
        &self.admission_key
    }
    pub fn descriptor_root(&self) -> &ContentHash {
        &self.descriptor_root
    }
    pub fn payload_root(&self) -> &ContentHash {
        &self.payload_root
    }
    pub fn decoded_review_root(&self) -> &ContentHash {
        &self.decoded_review_root
    }
    pub fn stored_projection_root(&self) -> &ContentHash {
        &self.stored_projection_root
    }
    pub fn snapshot(&self) -> &SnapshotRef {
        &self.snapshot
    }
    pub fn transaction_time(&self) -> Timestamp {
        self.transaction_time
    }
    pub fn review_ids(&self) -> &[ReviewRecordId] {
        &self.review_ids
    }

    /// Check every content/identity binding before accepting a journaled
    /// receipt as completion of this prepared attempt.
    pub fn verify_prepared(&self, prepared: &ReviewBundlePrepared) -> Result<()> {
        prepared.validate()?;
        if self.admission_key != prepared.admission_key
            || self.descriptor_root != prepared.descriptor_root
            || self.payload_root != prepared.payload_root
            || self.decoded_review_root != prepared.canonical_review_root
            || self.review_ids != prepared.expected_review_ids
        {
            return Err(Error::new(
                crate::ErrorKind::Conflict,
                "review admission receipt binding mismatch",
            ));
        }
        Ok(())
    }

    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql-review-admission-receipt/v1")),
            ("admission_key", V::string(self.admission_key.as_str())),
            ("descriptor_root", V::string(self.descriptor_root.as_str())),
            ("payload_root", V::string(self.payload_root.as_str())),
            (
                "decoded_review_root",
                V::string(self.decoded_review_root.as_str()),
            ),
            (
                "stored_projection_root",
                V::string(self.stored_projection_root.as_str()),
            ),
            ("snapshot", snapshot_projection(&self.snapshot)),
            (
                "transaction_time",
                V::string(self.transaction_time.canonical()),
            ),
            (
                "review_ids",
                V::Array(
                    self.review_ids
                        .iter()
                        .map(|id| V::string(id.as_str()))
                        .collect(),
                ),
            ),
        ])
    }
}

fn snapshot_projection(snapshot: &SnapshotRef) -> V {
    obj([
        ("backend", V::string(snapshot.backend().as_str())),
        ("pin", snapshot.pin().projection()),
    ])
}
fn snapshot_from_value(value: &V) -> Result<SnapshotRef> {
    value.closed(&["backend", "pin"], &[])?;
    Ok(SnapshotRef::new(
        crate::id::BackendId::new(value.field("backend")?.as_str()?)?,
        GraphPin::from_value(value.field("pin")?)?,
    ))
}
