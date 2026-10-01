//! Canonical trusted-acquisition bundle commitments and receipts.

use crate::claim::CandidateClaim;
use crate::id::{BundleId, ClaimId, ContentHash, ExtractionRunId, IdempotencyKey};
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

fn claim_payload_without_id(claim: &CandidateClaim) -> V {
    let V::Object(mut value) = claim.projection() else {
        unreachable!()
    };
    value.remove("claim_id");
    V::Object(value)
}

pub fn bundle_descriptor_root(
    id: &BundleId,
    extraction_run: &ExtractionRunId,
    validation_capture: &SnapshotRef,
    descriptor: &V,
    limits: Limits,
) -> Result<ContentHash> {
    descriptor.as_object()?;
    let value = obj([
        ("schema", V::string("ctxql-bundle-descriptor/v1")),
        ("bundle_id", V::string(id.as_str())),
        ("extraction_run", V::string(extraction_run.as_str())),
        ("validation_capture", validation_capture.projection()),
        ("descriptor", descriptor.clone()),
    ]);
    Ok(ContentHash::of_bytes(&value.canonical_bytes(limits)?))
}

pub fn canonical_claim_root(claims: &[CandidateClaim], limits: Limits) -> Result<ContentHash> {
    let mut ordered = claims.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.id().cmp(right.id()));
    let value = V::Array(
        ordered
            .into_iter()
            .map(CandidateClaim::projection)
            .collect(),
    );
    Ok(ContentHash::of_bytes(&value.canonical_bytes(limits)?))
}

pub fn stable_acquisition_v2_claim_id(claim: &CandidateClaim, limits: Limits) -> Result<ClaimId> {
    if claim
        .ext()
        .field("ctxql.acquisition.v2/claim_identity")?
        .as_str()?
        != "stable-component/v1"
    {
        return Err(Error::invalid("acquisition-v2 claim identity marker"));
    }
    claim
        .ext()
        .field("ctxql.acquisition.v2/component_ref")?
        .as_str()?;
    let value = obj([
        ("schema", V::string("ctxql-acquisition-v2-claim-id/v1")),
        ("payload", claim_payload_without_id(claim)),
    ]);
    let root = ContentHash::of_bytes(&value.canonical_bytes(limits)?);
    ClaimId::new(format!("urn:ctxql:claim:v2:{}", &root.as_str()[7..]))
}

fn uses_stable_acquisition_v2_identity(claim: &CandidateClaim) -> bool {
    claim
        .ext()
        .as_object()
        .ok()
        .and_then(|value| value.get("ctxql.acquisition.v2/claim_identity"))
        .and_then(|value| value.as_str().ok())
        == Some("stable-component/v1")
}

pub fn deterministic_claim_id(
    descriptor_root: &ContentHash,
    role: &str,
    claim: &CandidateClaim,
    limits: Limits,
) -> Result<ClaimId> {
    if role.is_empty() || role.len() > 256 || role.chars().any(char::is_control) {
        return Err(Error::invalid("claim role"));
    }
    let value = obj([
        ("schema", V::string("ctxql-acquisition-claim-id/v1")),
        ("descriptor_root", V::string(descriptor_root.as_str())),
        ("role", V::string(role)),
        ("payload", claim_payload_without_id(claim)),
    ]);
    let root = ContentHash::of_bytes(&value.canonical_bytes(limits)?);
    ClaimId::new(format!("urn:ctxql:claim:{}", &root.as_str()[7..]))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSemanticBundle {
    id: BundleId,
    extraction_run: ExtractionRunId,
    validation_capture: SnapshotRef,
    descriptor: V,
    descriptor_root: ContentHash,
    claims: Vec<CandidateClaim>,
    claim_roles: Vec<String>,
    payload_root: ContentHash,
    canonical_claim_root: ContentHash,
    admission_key: IdempotencyKey,
}
impl ValidatedSemanticBundle {
    pub fn new(
        id: BundleId,
        extraction_run: ExtractionRunId,
        validation_capture: SnapshotRef,
        descriptor: V,
        claims: Vec<(String, CandidateClaim)>,
        limits: Limits,
    ) -> Result<Self> {
        descriptor.as_object()?;
        if claims.is_empty() {
            return Err(Error::invalid("empty semantic bundle"));
        }
        let descriptor_root = bundle_descriptor_root(
            &id,
            &extraction_run,
            &validation_capture,
            &descriptor,
            limits,
        )?;
        let mut ids = BTreeSet::new();
        let mut roles = BTreeSet::new();
        for (role, claim) in &claims {
            if !roles.insert(role.as_str()) {
                return Err(Error::invalid("duplicate claim role"));
            }
            if !ids.insert(claim.id()) {
                return Err(Error::invalid("duplicate bundle claim"));
            }
            let expected = if uses_stable_acquisition_v2_identity(claim) {
                stable_acquisition_v2_claim_id(claim, limits)?
            } else {
                deterministic_claim_id(&descriptor_root, role, claim, limits)?
            };
            if claim.id() != &expected {
                return Err(Error::invalid("nondeterministic acquisition claim ID"));
            }
        }
        let claim_roles = claims
            .iter()
            .map(|(role, _)| role.clone())
            .collect::<Vec<_>>();
        let claims = claims
            .into_iter()
            .map(|(_, claim)| claim)
            .collect::<Vec<_>>();
        let payload = obj([
            ("schema", V::string("ctxql-semantic-bundle/v1")),
            ("descriptor_root", V::string(descriptor_root.as_str())),
            (
                "claims",
                V::Array(
                    claim_roles
                        .iter()
                        .zip(&claims)
                        .map(|(role, claim)| {
                            obj([("role", V::string(role)), ("claim", claim.projection())])
                        })
                        .collect(),
                ),
            ),
        ]);
        let payload_root = ContentHash::of_bytes(&payload.canonical_bytes(limits)?);
        let canonical_claim_root = canonical_claim_root(&claims, limits)?;
        let admission_key = IdempotencyKey::new(format!(
            "p6:{}",
            &ContentHash::of_bytes(
                &obj([
                    ("descriptor_root", V::string(descriptor_root.as_str())),
                    ("payload_root", V::string(payload_root.as_str())),
                ])
                .canonical_bytes(limits)?,
            )
            .as_str()[7..]
        ))?;
        Ok(Self {
            id,
            extraction_run,
            validation_capture,
            descriptor,
            descriptor_root,
            claims,
            claim_roles,
            payload_root,
            canonical_claim_root,
            admission_key,
        })
    }
    pub fn id(&self) -> &BundleId {
        &self.id
    }
    pub fn extraction_run(&self) -> &ExtractionRunId {
        &self.extraction_run
    }
    pub fn validation_capture(&self) -> &SnapshotRef {
        &self.validation_capture
    }
    pub fn descriptor_root(&self) -> &ContentHash {
        &self.descriptor_root
    }
    pub fn payload_root(&self) -> &ContentHash {
        &self.payload_root
    }
    pub fn canonical_claim_root(&self) -> &ContentHash {
        &self.canonical_claim_root
    }
    pub fn admission_key(&self) -> &IdempotencyKey {
        &self.admission_key
    }
    pub fn claims(&self) -> &[CandidateClaim] {
        &self.claims
    }
    pub fn claim_roles(&self) -> &[String] {
        &self.claim_roles
    }
    pub fn expected_claim_ids(&self) -> Vec<ClaimId> {
        self.claims.iter().map(|claim| claim.id().clone()).collect()
    }
    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql-semantic-bundle/v1")),
            ("bundle_id", V::string(self.id.as_str())),
            ("extraction_run", V::string(self.extraction_run.as_str())),
            ("validation_capture", self.validation_capture.projection()),
            ("descriptor", self.descriptor.clone()),
            ("descriptor_root", V::string(self.descriptor_root.as_str())),
            (
                "claims",
                V::Array(
                    self.claim_roles
                        .iter()
                        .zip(&self.claims)
                        .map(|(role, claim)| {
                            obj([("role", V::string(role)), ("claim", claim.projection())])
                        })
                        .collect(),
                ),
            ),
            ("payload_root", V::string(self.payload_root.as_str())),
            (
                "canonical_claim_root",
                V::string(self.canonical_claim_root.as_str()),
            ),
            ("admission_key", V::string(self.admission_key.as_str())),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticAdmissionReceipt {
    admission_key: IdempotencyKey,
    descriptor_root: ContentHash,
    payload_root: ContentHash,
    decoded_claim_root: ContentHash,
    stored_projection_root: ContentHash,
    snapshot: SnapshotRef,
    transaction_time: Timestamp,
    claim_ids: Vec<ClaimId>,
}
impl SemanticAdmissionReceipt {
    pub fn from_value(value: &V) -> Result<Self> {
        value.closed(
            &[
                "schema",
                "admission_key",
                "descriptor_root",
                "payload_root",
                "decoded_claim_root",
                "stored_projection_root",
                "snapshot",
                "transaction_time",
                "claim_ids",
            ],
            &[],
        )?;
        if value.field("schema")?.as_str()? != "ctxql-semantic-admission-receipt/v1" {
            return Err(Error::invalid("semantic admission receipt schema"));
        }
        Self::new(
            IdempotencyKey::new(value.field("admission_key")?.as_str()?)?,
            ContentHash::parse(value.field("descriptor_root")?.as_str()?)?,
            ContentHash::parse(value.field("payload_root")?.as_str()?)?,
            ContentHash::parse(value.field("decoded_claim_root")?.as_str()?)?,
            ContentHash::parse(value.field("stored_projection_root")?.as_str()?)?,
            snapshot_from_value(value.field("snapshot")?)?,
            Timestamp::parse(value.field("transaction_time")?.as_str()?)?,
            value
                .field("claim_ids")?
                .as_array()?
                .iter()
                .map(|id| ClaimId::new(id.as_str()?))
                .collect::<Result<_>>()?,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admission_key: IdempotencyKey,
        descriptor_root: ContentHash,
        payload_root: ContentHash,
        decoded_claim_root: ContentHash,
        stored_projection_root: ContentHash,
        snapshot: SnapshotRef,
        transaction_time: Timestamp,
        claim_ids: Vec<ClaimId>,
    ) -> Result<Self> {
        if claim_ids.is_empty()
            || claim_ids.iter().collect::<BTreeSet<_>>().len() != claim_ids.len()
        {
            return Err(Error::invalid("admission receipt claims"));
        }
        Ok(Self {
            admission_key,
            descriptor_root,
            payload_root,
            decoded_claim_root,
            stored_projection_root,
            snapshot,
            transaction_time,
            claim_ids,
        })
    }
    pub fn admission_key(&self) -> &IdempotencyKey {
        &self.admission_key
    }
    pub fn payload_root(&self) -> &ContentHash {
        &self.payload_root
    }
    pub fn snapshot(&self) -> &SnapshotRef {
        &self.snapshot
    }
    pub fn claim_ids(&self) -> &[ClaimId] {
        &self.claim_ids
    }
    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql-semantic-admission-receipt/v1")),
            ("admission_key", V::string(self.admission_key.as_str())),
            ("descriptor_root", V::string(self.descriptor_root.as_str())),
            ("payload_root", V::string(self.payload_root.as_str())),
            (
                "decoded_claim_root",
                V::string(self.decoded_claim_root.as_str()),
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
                "claim_ids",
                V::Array(
                    self.claim_ids
                        .iter()
                        .map(|id| V::string(id.as_str()))
                        .collect(),
                ),
            ),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionReceipt {
    admission_key: IdempotencyKey,
    admitted: SnapshotRef,
    projected: SnapshotRef,
}
impl ProjectionReceipt {
    pub fn from_value(value: &V) -> Result<Self> {
        value.closed(&["schema", "admission_key", "admitted", "projected"], &[])?;
        if value.field("schema")?.as_str()? != "ctxql-projection-receipt/v1" {
            return Err(Error::invalid("projection receipt schema"));
        }
        Self::new(
            IdempotencyKey::new(value.field("admission_key")?.as_str()?)?,
            snapshot_from_value(value.field("admitted")?)?,
            snapshot_from_value(value.field("projected")?)?,
        )
    }
    pub fn new(
        admission_key: IdempotencyKey,
        admitted: SnapshotRef,
        projected: SnapshotRef,
    ) -> Result<Self> {
        if admitted != projected {
            return Err(Error::invalid("projection receipt capture"));
        }
        Ok(Self {
            admission_key,
            admitted,
            projected,
        })
    }
    pub fn projected(&self) -> &SnapshotRef {
        &self.projected
    }
    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql-projection-receipt/v1")),
            ("admission_key", V::string(self.admission_key.as_str())),
            ("admitted", snapshot_projection(&self.admitted)),
            ("projected", snapshot_projection(&self.projected)),
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
