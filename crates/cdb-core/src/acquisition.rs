//! Portable trusted-acquisition state, safe journal records, and narrow capabilities.

use crate::contracts::IoFuture;
use crate::id::{AttemptId, BundleId, ClaimId, ContentHash, JobId};
use crate::review::{ReviewAdmissionReceipt, ReviewBundlePrepared};
use crate::semantic_admission::{
    ProjectionReceipt, SemanticAdmissionReceipt, ValidatedSemanticBundle,
};
use crate::snapshot::SnapshotRef;
use crate::{CanonicalValue as V, Error, Result, Timestamp};
use std::collections::BTreeSet;

fn obj(fields: impl IntoIterator<Item = (&'static str, V)>) -> V {
    V::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobState {
    Created,
    Acquiring,
    Converting,
    Planning,
    Extracting,
    Validating,
    Admitting,
    WaitingProjection,
    Completed,
    CompletedWithErrors,
    Failed,
    Cancelled,
    RecoveryRequired,
}
impl JobState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Acquiring => "acquiring",
            Self::Converting => "converting",
            Self::Planning => "planning",
            Self::Extracting => "extracting",
            Self::Validating => "validating",
            Self::Admitting => "admitting",
            Self::WaitingProjection => "waiting_projection",
            Self::Completed => "completed",
            Self::CompletedWithErrors => "completed_with_errors",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::RecoveryRequired => "recovery_required",
        }
    }
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::CompletedWithErrors | Self::Failed | Self::Cancelled
        )
    }
    pub fn permits(self, next: Self) -> bool {
        use JobState::*;
        matches!(
            (self, next),
            (Created, Acquiring)
                | (Acquiring, Converting)
                | (Converting, Planning)
                | (Planning, Extracting)
                | (Extracting, Validating)
                | (Validating, Admitting)
                | (Admitting, Admitting)
                | (Admitting, WaitingProjection)
                | (Admitting, Completed)
                | (Admitting, CompletedWithErrors)
                | (WaitingProjection, Completed)
                | (WaitingProjection, CompletedWithErrors)
                | (RecoveryRequired, Admitting)
        ) || (!self.terminal() && matches!(next, Failed | Cancelled | RecoveryRequired))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleState {
    CandidateRejected,
    Validated,
    Prepared,
    AdmissionUnknown,
    Admitted,
    Projected,
    Conflict,
}
impl BundleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CandidateRejected => "candidate_rejected",
            Self::Validated => "validated",
            Self::Prepared => "prepared",
            Self::AdmissionUnknown => "admission_unknown",
            Self::Admitted => "admitted",
            Self::Projected => "projected",
            Self::Conflict => "conflict",
        }
    }
    pub fn permits(self, next: Self) -> bool {
        use BundleState::*;
        matches!(
            (self, next),
            (Validated, Prepared)
                | (Prepared, AdmissionUnknown)
                | (Prepared, Admitted)
                | (AdmissionUnknown, Admitted)
                | (AdmissionUnknown, Conflict)
                | (Prepared, Conflict)
                | (Admitted, Projected)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcquisitionFailureClass {
    Source,
    Conversion,
    Planning,
    ProviderTransport,
    ProviderGrammar,
    SourceCoordinate,
    Ontology,
    Entity,
    SemanticValidation,
    Authorization,
    Writer,
    AcknowledgementRecovery,
    Projection,
    Cancellation,
    Limit,
}
impl AcquisitionFailureClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Conversion => "conversion",
            Self::Planning => "planning",
            Self::ProviderTransport => "provider_transport",
            Self::ProviderGrammar => "provider_grammar",
            Self::SourceCoordinate => "source_coordinate",
            Self::Ontology => "ontology",
            Self::Entity => "entity",
            Self::SemanticValidation => "semantic_validation",
            Self::Authorization => "authorization",
            Self::Writer => "writer",
            Self::AcknowledgementRecovery => "acknowledgement_recovery",
            Self::Projection => "projection",
            Self::Cancellation => "cancellation",
            Self::Limit => "limit",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceObject {
    hash: ContentHash,
    bytes: Vec<u8>,
}
impl SourceObject {
    pub fn new(hash: ContentHash, bytes: Vec<u8>, max_bytes: usize) -> Result<Self> {
        if bytes.len() > max_bytes || ContentHash::of_bytes(&bytes) != hash {
            return Err(Error::invalid("source object"));
        }
        Ok(Self { hash, bytes })
    }
    pub fn hash(&self) -> &ContentHash {
        &self.hash
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub trait SourceObjectReader: Send + Sync {
    fn read<'a>(&'a self, hash: &'a ContentHash, max_bytes: usize) -> IoFuture<'a, SourceObject>;
}
pub trait SourceObjectWriter: Send + Sync {
    fn put<'a>(&'a self, bytes: &'a [u8], max_bytes: usize) -> IoFuture<'a, ContentHash>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundlePrepared {
    pub job_id: JobId,
    pub attempt_id: AttemptId,
    pub bundle_id: BundleId,
    pub admission_key: String,
    pub descriptor_root: ContentHash,
    pub payload_root: ContentHash,
    pub canonical_claim_root: ContentHash,
    pub expected_claim_ids: Vec<ClaimId>,
    pub validation_capture: SnapshotRef,
    pub source_selector_root: ContentHash,
    pub safe_counts: V,
    pub recorded_at: Timestamp,
}
impl BundlePrepared {
    pub fn from_value(value: &V) -> Result<Self> {
        value.closed(
            &[
                "schema",
                "job_id",
                "attempt_id",
                "bundle_id",
                "admission_key",
                "descriptor_root",
                "payload_root",
                "canonical_claim_root",
                "expected_claim_ids",
                "validation_capture",
                "source_selector_root",
                "safe_counts",
                "recorded_at",
            ],
            &[],
        )?;
        if value.field("schema")?.as_str()? != "ctxql-bundle-prepared/v1" {
            return Err(Error::invalid("prepared bundle schema"));
        }
        let capture = value.field("validation_capture")?;
        capture.closed(&["backend", "pin"], &[])?;
        let prepared = Self {
            job_id: JobId::new(value.field("job_id")?.as_str()?)?,
            attempt_id: AttemptId::new(value.field("attempt_id")?.as_str()?)?,
            bundle_id: BundleId::new(value.field("bundle_id")?.as_str()?)?,
            admission_key: value.field("admission_key")?.as_str()?.to_owned(),
            descriptor_root: ContentHash::parse(value.field("descriptor_root")?.as_str()?)?,
            payload_root: ContentHash::parse(value.field("payload_root")?.as_str()?)?,
            canonical_claim_root: ContentHash::parse(
                value.field("canonical_claim_root")?.as_str()?,
            )?,
            expected_claim_ids: value
                .field("expected_claim_ids")?
                .as_array()?
                .iter()
                .map(|id| ClaimId::new(id.as_str()?))
                .collect::<Result<_>>()?,
            validation_capture: SnapshotRef::new(
                crate::id::BackendId::new(capture.field("backend")?.as_str()?)?,
                crate::snapshot::GraphPin::from_value(capture.field("pin")?)?,
            ),
            source_selector_root: ContentHash::parse(
                value.field("source_selector_root")?.as_str()?,
            )?,
            safe_counts: value.field("safe_counts")?.clone(),
            recorded_at: Timestamp::parse(value.field("recorded_at")?.as_str()?)?,
        };
        prepared.validate()?;
        Ok(prepared)
    }

    pub fn validate(&self) -> Result<()> {
        if self.expected_claim_ids.is_empty()
            || self
                .expected_claim_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.expected_claim_ids.len()
            || self.admission_key.is_empty()
        {
            return Err(Error::invalid("prepared bundle"));
        }
        self.safe_counts.as_object()?;
        Ok(())
    }
    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql-bundle-prepared/v1")),
            ("job_id", V::string(self.job_id.as_str())),
            ("attempt_id", V::string(self.attempt_id.as_str())),
            ("bundle_id", V::string(self.bundle_id.as_str())),
            ("admission_key", V::string(&self.admission_key)),
            ("descriptor_root", V::string(self.descriptor_root.as_str())),
            ("payload_root", V::string(self.payload_root.as_str())),
            (
                "canonical_claim_root",
                V::string(self.canonical_claim_root.as_str()),
            ),
            (
                "expected_claim_ids",
                V::Array(
                    self.expected_claim_ids
                        .iter()
                        .map(|id| V::string(id.as_str()))
                        .collect(),
                ),
            ),
            (
                "validation_capture",
                obj([
                    (
                        "backend",
                        V::string(self.validation_capture.backend().as_str()),
                    ),
                    ("pin", self.validation_capture.pin().projection()),
                ]),
            ),
            (
                "source_selector_root",
                V::string(self.source_selector_root.as_str()),
            ),
            ("safe_counts", self.safe_counts.clone()),
            ("recorded_at", V::string(self.recorded_at.canonical())),
        ])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupersededPreparedKind {
    Review,
    Business,
}
impl SupersededPreparedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::Business => "business",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "review" => Ok(Self::Review),
            "business" => Ok(Self::Business),
            _ => Err(Error::invalid("superseded prepared kind")),
        }
    }
}

/// Durable proof that one prepared attempt was absent while the writer lease
/// was held, and was therefore replaced at the observed current head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedSupersededAbsent {
    pub job_id: JobId,
    pub kind: SupersededPreparedKind,
    pub predecessor_bundle_id: BundleId,
    pub predecessor_attempt_id: AttemptId,
    pub successor_bundle_id: BundleId,
    pub successor_attempt_id: AttemptId,
    pub successor_capture: SnapshotRef,
    pub recorded_at: Timestamp,
}
impl PreparedSupersededAbsent {
    pub fn validate(&self) -> Result<()> {
        if self.predecessor_bundle_id == self.successor_bundle_id
            || self.predecessor_attempt_id == self.successor_attempt_id
        {
            return Err(Error::invalid("superseded absent successor identity"));
        }
        Ok(())
    }
    pub fn from_value(value: &V) -> Result<Self> {
        value.closed(
            &[
                "schema",
                "status",
                "job_id",
                "kind",
                "predecessor_bundle_id",
                "predecessor_attempt_id",
                "successor_bundle_id",
                "successor_attempt_id",
                "successor_capture",
                "recorded_at",
            ],
            &[],
        )?;
        if value.field("schema")?.as_str()? != "ctxql-prepared-supersession/v1"
            || value.field("status")?.as_str()? != "superseded_absent"
        {
            return Err(Error::invalid("superseded absent schema"));
        }
        let capture = value.field("successor_capture")?;
        capture.closed(&["backend", "pin"], &[])?;
        let record = Self {
            job_id: JobId::new(value.field("job_id")?.as_str()?)?,
            kind: SupersededPreparedKind::parse(value.field("kind")?.as_str()?)?,
            predecessor_bundle_id: BundleId::new(value.field("predecessor_bundle_id")?.as_str()?)?,
            predecessor_attempt_id: AttemptId::new(
                value.field("predecessor_attempt_id")?.as_str()?,
            )?,
            successor_bundle_id: BundleId::new(value.field("successor_bundle_id")?.as_str()?)?,
            successor_attempt_id: AttemptId::new(value.field("successor_attempt_id")?.as_str()?)?,
            successor_capture: SnapshotRef::new(
                crate::id::BackendId::new(capture.field("backend")?.as_str()?)?,
                crate::snapshot::GraphPin::from_value(capture.field("pin")?)?,
            ),
            recorded_at: Timestamp::parse(value.field("recorded_at")?.as_str()?)?,
        };
        record.validate()?;
        Ok(record)
    }
    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql-prepared-supersession/v1")),
            ("status", V::string("superseded_absent")),
            ("job_id", V::string(self.job_id.as_str())),
            ("kind", V::string(self.kind.as_str())),
            (
                "predecessor_bundle_id",
                V::string(self.predecessor_bundle_id.as_str()),
            ),
            (
                "predecessor_attempt_id",
                V::string(self.predecessor_attempt_id.as_str()),
            ),
            (
                "successor_bundle_id",
                V::string(self.successor_bundle_id.as_str()),
            ),
            (
                "successor_attempt_id",
                V::string(self.successor_attempt_id.as_str()),
            ),
            (
                "successor_capture",
                obj([
                    (
                        "backend",
                        V::string(self.successor_capture.backend().as_str()),
                    ),
                    ("pin", self.successor_capture.pin().projection()),
                ]),
            ),
            ("recorded_at", V::string(self.recorded_at.canonical())),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionRecovery {
    Absent,
    Exact(Box<SemanticAdmissionReceipt>),
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewAdmissionRecovery {
    Absent,
    Exact(Box<ReviewAdmissionReceipt>),
    Conflict,
}

pub trait SemanticBundleWriter: Send + Sync {
    fn preflight<'a>(&'a self, bundle: &'a ValidatedSemanticBundle) -> IoFuture<'a, ()>;
    fn recover<'a>(&'a self, prepared: &'a BundlePrepared) -> IoFuture<'a, AdmissionRecovery>;
    /// Perform final history recovery and, only when absent, admission under
    /// one process-wide writer critical section.
    fn recover_or_admit<'a>(
        &'a self,
        prepared: &'a BundlePrepared,
        bundle: &'a ValidatedSemanticBundle,
    ) -> IoFuture<'a, SemanticAdmissionReceipt>;
}

pub trait AcquisitionControl: Send + Sync {
    fn append_prepared<'a>(&'a self, prepared: &'a BundlePrepared) -> IoFuture<'a, ()>;
    fn prepared<'a>(&'a self, bundle: &'a BundleId) -> IoFuture<'a, Option<BundlePrepared>>;
    /// Enumerate durable prepared records in deterministic bundle-ID order.
    /// Startup recovery uses this before provider work both to finalize lost
    /// acknowledgements and to identify already completed durable jobs.
    fn prepared_records(&self) -> IoFuture<'_, Vec<BundlePrepared>>;
    fn admission<'a>(
        &'a self,
        bundle: &'a BundleId,
    ) -> IoFuture<'a, Option<SemanticAdmissionReceipt>>;
    fn append_admission<'a>(
        &'a self,
        bundle: &'a BundleId,
        receipt: &'a SemanticAdmissionReceipt,
    ) -> IoFuture<'a, ()>;
    fn append_projection<'a>(
        &'a self,
        bundle: &'a BundleId,
        receipt: &'a ProjectionReceipt,
    ) -> IoFuture<'a, ()>;
    fn append_review_prepared<'a>(
        &'a self,
        _prepared: &'a ReviewBundlePrepared,
    ) -> IoFuture<'a, ()> {
        Box::pin(async {
            Err(Error::new(
                crate::ErrorKind::Unsupported,
                "review prepared control",
            ))
        })
    }
    fn review_prepared<'a>(
        &'a self,
        _bundle: &'a BundleId,
    ) -> IoFuture<'a, Option<ReviewBundlePrepared>> {
        Box::pin(async { Ok(None) })
    }
    /// Enumerate durable review attempts in deterministic bundle-ID order.
    fn review_prepared_records(&self) -> IoFuture<'_, Vec<ReviewBundlePrepared>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn review_admission<'a>(
        &'a self,
        _bundle: &'a BundleId,
    ) -> IoFuture<'a, Option<ReviewAdmissionReceipt>> {
        Box::pin(async { Ok(None) })
    }
    fn append_review_admission<'a>(
        &'a self,
        _bundle: &'a BundleId,
        _receipt: &'a ReviewAdmissionReceipt,
    ) -> IoFuture<'a, ()> {
        Box::pin(async {
            Err(Error::new(
                crate::ErrorKind::Unsupported,
                "review admission control",
            ))
        })
    }
    fn append_superseded_absent<'a>(
        &'a self,
        _record: &'a PreparedSupersededAbsent,
    ) -> IoFuture<'a, ()> {
        Box::pin(async {
            Err(Error::new(
                crate::ErrorKind::Unsupported,
                "prepared supersession control",
            ))
        })
    }
    fn superseded_absent<'a>(
        &'a self,
        _predecessor: &'a BundleId,
    ) -> IoFuture<'a, Option<PreparedSupersededAbsent>> {
        Box::pin(async { Ok(None) })
    }
    fn superseded_absent_records(&self) -> IoFuture<'_, Vec<PreparedSupersededAbsent>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

pub trait ProjectionObserver: Send + Sync {
    fn wait_exact<'a>(
        &'a self,
        admission: &'a SemanticAdmissionReceipt,
    ) -> IoFuture<'a, ProjectionReceipt>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_machines_reject_terminal_and_skipped_transitions() {
        assert!(JobState::Created.permits(JobState::Acquiring));
        assert!(!JobState::Created.permits(JobState::Extracting));
        assert!(!JobState::Completed.permits(JobState::Acquiring));
        assert!(BundleState::Prepared.permits(BundleState::AdmissionUnknown));
        assert!(!BundleState::Prepared.permits(BundleState::Projected));
    }

    #[test]
    fn source_object_rehashes_bytes() {
        let bytes = b"exact".to_vec();
        assert!(SourceObject::new(ContentHash::of_bytes(&bytes), bytes.clone(), 5).is_ok());
        assert!(SourceObject::new(ContentHash::of_bytes(b"other"), bytes, 5).is_err());
    }
}
