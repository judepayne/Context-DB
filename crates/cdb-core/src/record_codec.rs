//! Bounded lossless storage wire format, not a canonical hash domain or credential.
//! Callers must still validate authority, ancestry, and immutable-key conflicts.
use crate::admission::*;
use crate::artifact::{ArtifactRef, PublishedArtifact};
use crate::claim::{AdmittedClaim, CandidateClaim, LifecycleAssertion, TypedLiteral};
use crate::id::*;
use crate::snapshot::{GraphPin, ProjectionCheckpoint, SnapshotRef};
use crate::value::obj;
use crate::{CanonicalValue as V, Error, Limits, Result, Timestamp};

pub const SCHEMA: &str = "ctxql-storage/v1";
fn envelope(kind: &str, payload: V) -> V {
    obj([
        ("schema", V::string(SCHEMA)),
        ("kind", V::string(kind)),
        ("payload", payload),
    ])
}
fn payload<'a>(v: &'a V, kind: &str) -> Result<&'a V> {
    v.closed(&["schema", "kind", "payload"], &[])?;
    if v.field("schema")?.as_str()? != SCHEMA || v.field("kind")?.as_str()? != kind {
        return Err(Error::invalid("storage schema/kind"));
    }
    v.field("payload")
}
fn bounded(v: &V, limits: Limits) -> Result<()> {
    v.canonical_bytes(limits)?;
    Ok(())
}
fn resource_kind(s: &str) -> Result<ResourceKind> {
    match s {
        "ontology" => Ok(ResourceKind::Ontology),
        "label" => Ok(ResourceKind::Label),
        "policy" => Ok(ResourceKind::Policy),
        "identity" => Ok(ResourceKind::Identity),
        "source" => Ok(ResourceKind::SourceDescriptor),
        "artifact" => Ok(ResourceKind::ArtifactDescriptor),
        "run" => Ok(ResourceKind::RunDescriptor),
        "lifecycle_event" => Ok(ResourceKind::LifecycleEvent),
        _ => Err(Error::invalid("resource kind")),
    }
}
fn resource(v: &V) -> Result<DependencyRecord> {
    v.closed(&["schema", "id", "kind", "facts"], &[])?;
    let facts = v
        .field("facts")?
        .as_array()?
        .iter()
        .map(|f| {
            f.closed(&["predicate", "term"], &[])?;
            let t = f.field("term")?;
            let term = if t.field("kind")?.as_str()? == "reference" {
                t.closed(&["kind", "value"], &[])?;
                FactTerm::Reference(ResourceId::new(t.field("value")?.as_str()?)?)
            } else {
                FactTerm::Literal(TypedLiteral::from_value(t)?)
            };
            Ok(Fact::new(Iri::new(f.field("predicate")?.as_str()?)?, term))
        })
        .collect::<Result<Vec<_>>>()?;
    DependencyRecord::new(
        v.field("schema")?.as_str()?,
        ResourceId::new(v.field("id")?.as_str()?)?,
        resource_kind(v.field("kind")?.as_str()?)?,
        facts,
    )
}
fn resource_change(v: &V) -> Result<ResourceChange> {
    let r = match v.field("operation")?.as_str()? {
        "add" => {
            v.closed(&["operation", "record"], &[])?;
            ResourceChange::Add(resource(v.field("record")?)?)
        }
        "replace_mutable" => {
            v.closed(&["operation", "previous", "record"], &[])?;
            ResourceChange::ReplaceMutable {
                previous: ContentHash::parse(v.field("previous")?.as_str()?)?,
                record: resource(v.field("record")?)?,
            }
        }
        "retract_mutable" => {
            v.closed(&["operation", "previous", "id", "kind"], &[])?;
            ResourceChange::RetractMutable {
                previous: ContentHash::parse(v.field("previous")?.as_str()?)?,
                id: ResourceId::new(v.field("id")?.as_str()?)?,
                kind: resource_kind(v.field("kind")?.as_str()?)?,
            }
        }
        _ => return Err(Error::invalid("resource operation")),
    };
    r.validate()?;
    Ok(r)
}
fn artifact_value(a: &PublishedArtifact, limits: Limits) -> Result<V> {
    let n = a.content().len().checked_mul(2).ok_or_else(Error::limit)?;
    if a.content().len() > limits.input_bytes() || n > limits.output_bytes() || n > limits.work() {
        return Err(Error::limit());
    }
    let mut hex = String::with_capacity(n);
    const DIGITS: &[u8] = b"0123456789abcdef";
    for b in a.content() {
        hex.push(DIGITS[(b >> 4) as usize] as char);
        hex.push(DIGITS[(b & 15) as usize] as char);
    }
    Ok(obj([
        ("reference", a.reference().projection()),
        ("hex", V::string(hex)),
    ]))
}
fn artifact(v: &V, limits: Limits) -> Result<PublishedArtifact> {
    v.closed(&["reference", "hex"], &[])?;
    let hex = v.field("hex")?.as_str()?.as_bytes();
    if hex.len() / 2 > limits.input_bytes() || hex.len() > limits.work() {
        return Err(Error::limit());
    }
    if hex.len() % 2 != 0 {
        return Err(Error::invalid("odd artifact hex"));
    }
    fn digit(b: u8) -> Result<u8> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(Error::invalid("artifact hex")),
        }
    }
    let bytes = hex
        .chunks_exact(2)
        .map(|c| Ok(digit(c[0])? * 16 + digit(c[1])?))
        .collect::<Result<Vec<_>>>()?;
    PublishedArtifact::new(
        ArtifactRef::from_value(v.field("reference")?)?,
        bytes,
        limits,
    )
}
fn timed(kind: &str, candidate: V, time: Timestamp) -> V {
    obj([
        ("kind", V::string(kind)),
        ("candidate", candidate),
        ("transaction_time", V::string(time.canonical())),
    ])
}
fn record_value(r: &ExportRecord, limits: Limits) -> Result<V> {
    Ok(match r {
        ExportRecord::Claim(c) => {
            if c.candidate().is_lifecycle_assertion() {
                return Err(Error::invalid("lifecycle requires wrapper"));
            }
            timed("claim", c.candidate().projection(), c.transaction_time())
        }
        ExportRecord::Lifecycle {
            assertion,
            transaction_time,
        } => timed("lifecycle", assertion.projection(), *transaction_time),
        ExportRecord::Resource(r) => {
            obj([("kind", V::string("resource")), ("value", r.projection())])
        }
        ExportRecord::Artifact(a) => obj([
            ("kind", V::string("artifact")),
            ("value", artifact_value(a, limits)?),
        ]),
    })
}
fn record(v: &V, limits: Limits) -> Result<ExportRecord> {
    match v.field("kind")?.as_str()? {
        k @ ("claim" | "lifecycle") => {
            v.closed(&["kind", "candidate", "transaction_time"], &[])?;
            let time = Timestamp::parse(v.field("transaction_time")?.as_str()?)?;
            if k == "lifecycle" {
                Ok(ExportRecord::Lifecycle {
                    assertion: LifecycleAssertion::from_value(v.field("candidate")?)?,
                    transaction_time: time,
                })
            } else {
                let c = CandidateClaim::from_value(v.field("candidate")?)?;
                if c.is_lifecycle_assertion() {
                    return Err(Error::invalid("lifecycle requires wrapper"));
                }
                Ok(ExportRecord::Claim(Box::new(AdmittedClaim::assign(
                    c, time,
                ))))
            }
        }
        "resource" => {
            v.closed(&["kind", "value"], &[])?;
            Ok(ExportRecord::Resource(resource(v.field("value")?)?))
        }
        "artifact" => {
            v.closed(&["kind", "value"], &[])?;
            Ok(ExportRecord::Artifact(artifact(v.field("value")?, limits)?))
        }
        _ => Err(Error::invalid("record kind")),
    }
}
pub fn encode_record(r: &ExportRecord, limits: Limits) -> Result<Vec<u8>> {
    envelope("record", record_value(r, limits)?).canonical_bytes(limits)
}
pub fn decode_record(bytes: &[u8], limits: Limits) -> Result<ExportRecord> {
    record(payload(&V::parse(bytes, limits)?, "record")?, limits)
}
pub fn encode_change(c: &RecordChange, limits: Limits) -> Result<Vec<u8>> {
    let v = match c {
        RecordChange::Resource(r) => {
            r.validate()?;
            obj([
                ("kind", V::string("resource_change")),
                ("value", r.projection()),
            ])
        }
        RecordChange::ClaimAdded(c) => record_value(&ExportRecord::Claim(c.clone()), limits)?,
        RecordChange::LifecycleAdded {
            assertion,
            transaction_time,
        } => record_value(
            &ExportRecord::Lifecycle {
                assertion: assertion.clone(),
                transaction_time: *transaction_time,
            },
            limits,
        )?,
        RecordChange::ArtifactAdded(a) => obj([
            ("kind", V::string("artifact")),
            ("value", artifact_value(a, limits)?),
        ]),
    };
    envelope("change", v).canonical_bytes(limits)
}
pub fn decode_change(bytes: &[u8], limits: Limits) -> Result<RecordChange> {
    let v = V::parse(bytes, limits)?;
    let p = payload(&v, "change")?;
    if p.field("kind")?.as_str()? == "resource_change" {
        p.closed(&["kind", "value"], &[])?;
        return Ok(RecordChange::Resource(resource_change(p.field("value")?)?));
    }
    match record(p, limits)? {
        ExportRecord::Claim(c) => Ok(RecordChange::ClaimAdded(c)),
        ExportRecord::Lifecycle {
            assertion,
            transaction_time,
        } => Ok(RecordChange::LifecycleAdded {
            assertion,
            transaction_time,
        }),
        ExportRecord::Artifact(a) => Ok(RecordChange::ArtifactAdded(a)),
        ExportRecord::Resource(_) => Err(Error::invalid("change requires resource operation")),
    }
}
/// Complete request identity, including backend (unlike SnapshotRef::projection).
pub fn snapshot_value(s: &SnapshotRef) -> V {
    envelope(
        "snapshot",
        obj([
            ("backend", V::string(s.backend().as_str())),
            ("pin", s.pin().projection()),
        ]),
    )
}
pub fn snapshot_from_value(v: &V, limits: Limits) -> Result<SnapshotRef> {
    bounded(v, limits)?;
    let p = payload(v, "snapshot")?;
    p.closed(&["backend", "pin"], &[])?;
    Ok(SnapshotRef::new(
        BackendId::new(p.field("backend")?.as_str()?)?,
        GraphPin::from_value(p.field("pin")?)?,
    ))
}
pub fn checkpoint_value(c: &ProjectionCheckpoint) -> V {
    envelope(
        "checkpoint",
        obj([
            ("snapshot", snapshot_value(c.snapshot())),
            ("schema", V::string(c.schema().as_str())),
            ("generation", V::string(c.generation().as_str())),
            ("algorithm", V::string(c.algorithm().as_str())),
        ]),
    )
}
pub fn checkpoint_from_value(v: &V, limits: Limits) -> Result<ProjectionCheckpoint> {
    bounded(v, limits)?;
    let p = payload(v, "checkpoint")?;
    p.closed(&["snapshot", "schema", "generation", "algorithm"], &[])?;
    ProjectionCheckpoint::new(
        snapshot_from_value(p.field("snapshot")?, limits)?,
        VersionId::new(p.field("schema")?.as_str()?)?,
        VersionId::new(p.field("generation")?.as_str()?)?,
        Iri::new(p.field("algorithm")?.as_str()?)?,
    )
}
