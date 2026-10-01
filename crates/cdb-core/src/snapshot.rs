use crate::id::*;
use crate::value::obj;
use crate::{CanonicalValue as V, Error, Result, Timestamp};

fn numeric_revision(snapshot: &SnapshotRef) -> Result<u64> {
    let revision = snapshot.pin().revision().as_str();
    let t = revision
        .parse::<u64>()
        .map_err(|_| Error::invalid("semantic capture numeric revision"))?;
    if t.to_string() != revision {
        return Err(Error::invalid("semantic capture canonical revision"));
    }
    Ok(t)
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GraphPin {
    authority: AuthorityId,
    graph: GraphId,
    revision: VersionId,
    receipt: ResourceId,
}
impl GraphPin {
    pub fn new(
        authority: AuthorityId,
        graph: GraphId,
        revision: VersionId,
        receipt: ResourceId,
    ) -> Self {
        Self {
            authority,
            graph,
            revision,
            receipt,
        }
    }
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(&["authority", "graph", "revision", "receipt"], &[])?;
        Ok(Self::new(
            AuthorityId::new(v.field("authority")?.as_str()?)?,
            GraphId::new(v.field("graph")?.as_str()?)?,
            VersionId::new(v.field("revision")?.as_str()?)?,
            ResourceId::new(v.field("receipt")?.as_str()?)?,
        ))
    }
    pub fn authority(&self) -> &AuthorityId {
        &self.authority
    }
    pub fn graph(&self) -> &GraphId {
        &self.graph
    }
    pub fn revision(&self) -> &VersionId {
        &self.revision
    }
    pub fn receipt(&self) -> &ResourceId {
        &self.receipt
    }
    pub fn projection(&self) -> V {
        obj([
            ("authority", V::string(self.authority.as_str())),
            ("graph", V::string(self.graph.as_str())),
            ("revision", V::string(self.revision.as_str())),
            ("receipt", V::string(self.receipt.as_str())),
        ])
    }
}
/// A ref is a request, never proof of existence or permission. Authority spelling must be backend-scoped.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SnapshotRef {
    backend: BackendId,
    pin: GraphPin,
}
impl SnapshotRef {
    pub fn new(backend: BackendId, pin: GraphPin) -> Self {
        Self { backend, pin }
    }
    pub fn backend(&self) -> &BackendId {
        &self.backend
    }
    pub fn pin(&self) -> &GraphPin {
        &self.pin
    }
    pub fn same_authority(&self, other: &Self) -> bool {
        self.backend == other.backend
            && self.pin.authority == other.pin.authority
            && self.pin.graph == other.pin.graph
    }
    pub fn projection(&self) -> V {
        self.pin.projection()
    }
}

/// Evidence that one exact semantic revision can be reconstructed.
///
/// This deliberately proves only the named `(t, commit CID)` pair. It does not
/// assert that the point is the source's oldest retained revision, nor that all
/// revisions between this point and another capture remain available.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryAvailabilityEvidence {
    exact_capture: SnapshotRef,
}
impl HistoryAvailabilityEvidence {
    pub fn new(exact_capture: SnapshotRef) -> Result<Self> {
        numeric_revision(&exact_capture)?;
        Ok(Self { exact_capture })
    }
    pub fn exact_capture(&self) -> &SnapshotRef {
        &self.exact_capture
    }
    pub fn exact_t(&self) -> u64 {
        numeric_revision(&self.exact_capture).expect("validated semantic revision")
    }
    pub fn exact_commit_cid(&self) -> &ResourceId {
        self.exact_capture.pin().receipt()
    }

    /// Compatibility spelling only. This is an exact-point proof, not an
    /// assertion that the point is the earliest available history.
    #[deprecated(note = "use exact_capture; no global history horizon is proved")]
    pub fn earliest_available(&self) -> &SnapshotRef {
        self.exact_capture()
    }
    /// Compatibility spelling only; this value is not a retention boundary.
    #[deprecated(note = "use exact_t; no global history horizon is proved")]
    pub fn earliest_t(&self) -> u64 {
        self.exact_t()
    }
    /// Compatibility spelling only; this CID belongs to the exact proof point.
    #[deprecated(note = "use exact_commit_cid; no global history horizon is proved")]
    pub fn earliest_commit_cid(&self) -> &ResourceId {
        self.exact_commit_cid()
    }
}

/// Compatibility alias. Despite the legacy name, this proves one exact point,
/// not a global oldest-available horizon.
#[deprecated(note = "use HistoryAvailabilityEvidence")]
pub type HistoryHorizonEvidence = HistoryAvailabilityEvidence;

/// Exact read-only semantic-ledger capture.
///
/// Canonical mapping to the existing neutral identity is fixed as: ledger identity
/// to `GraphPin::graph`, numeric transaction `t` to the canonical decimal revision,
/// and the full commit CID to `GraphPin::receipt`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticCapture {
    requested_as_of: Option<Timestamp>,
    snapshot: SnapshotRef,
    history_availability: HistoryAvailabilityEvidence,
}
impl SemanticCapture {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        requested_as_of: Option<Timestamp>,
        backend: BackendId,
        authority: AuthorityId,
        ledger: GraphId,
        t: u64,
        commit_cid: ResourceId,
        verified_history_t: u64,
        verified_history_commit_cid: ResourceId,
    ) -> Result<Self> {
        let snapshot = semantic_snapshot(
            backend.clone(),
            authority.clone(),
            ledger.clone(),
            t,
            commit_cid,
        )?;
        let verified_history = semantic_snapshot(
            backend,
            authority,
            ledger,
            verified_history_t,
            verified_history_commit_cid,
        )?;
        Self::from_snapshot(
            requested_as_of,
            snapshot,
            HistoryAvailabilityEvidence::new(verified_history)?,
        )
    }
    pub fn from_snapshot(
        requested_as_of: Option<Timestamp>,
        snapshot: SnapshotRef,
        history_availability: HistoryAvailabilityEvidence,
    ) -> Result<Self> {
        numeric_revision(&snapshot)?;
        if history_availability.exact_capture() != &snapshot {
            return Err(Error::invalid("semantic history availability"));
        }
        Ok(Self {
            requested_as_of,
            snapshot,
            history_availability,
        })
    }
    pub fn requested_as_of(&self) -> Option<Timestamp> {
        self.requested_as_of
    }
    pub fn snapshot(&self) -> &SnapshotRef {
        &self.snapshot
    }
    pub fn ledger(&self) -> &GraphId {
        self.snapshot.pin().graph()
    }
    pub fn t(&self) -> u64 {
        numeric_revision(&self.snapshot).expect("validated semantic revision")
    }
    pub fn commit_cid(&self) -> &ResourceId {
        self.snapshot.pin().receipt()
    }
    pub fn history_availability(&self) -> &HistoryAvailabilityEvidence {
        &self.history_availability
    }
    /// Compatibility spelling only. The returned evidence proves one exact
    /// history point, not an oldest retained revision.
    #[deprecated(note = "use history_availability; no global horizon is proved")]
    #[allow(deprecated)]
    pub fn history_horizon(&self) -> &HistoryHorizonEvidence {
        &self.history_availability
    }
}

fn semantic_snapshot(
    backend: BackendId,
    authority: AuthorityId,
    ledger: GraphId,
    t: u64,
    commit_cid: ResourceId,
) -> Result<SnapshotRef> {
    Ok(SnapshotRef::new(
        backend,
        GraphPin::new(
            authority,
            ledger,
            VersionId::new(t.to_string())?,
            commit_cid,
        ),
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionCheckpoint {
    snapshot: SnapshotRef,
    schema: VersionId,
    generation: VersionId,
    algorithm: Iri,
}
impl ProjectionCheckpoint {
    pub fn new(
        snapshot: SnapshotRef,
        schema: VersionId,
        generation: VersionId,
        algorithm: Iri,
    ) -> Result<Self> {
        if !matches!(
            schema.as_str(),
            "ctxql-projection/v1" | "ctxql-semantic-rdf/v1"
        ) {
            return Err(Error::invalid("projection schema"));
        }
        Ok(Self {
            snapshot,
            schema,
            generation,
            algorithm,
        })
    }
    pub fn snapshot(&self) -> &SnapshotRef {
        &self.snapshot
    }
    pub fn schema(&self) -> &VersionId {
        &self.schema
    }
    pub fn generation(&self) -> &VersionId {
        &self.generation
    }
    pub fn algorithm(&self) -> &Iri {
        &self.algorithm
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageCursor {
    snapshot: SnapshotRef,
    stream: ResourceId,
    position: VersionId,
}
impl PageCursor {
    /// Trusted adapter cursor; not an authorization handle.
    pub fn new(snapshot: SnapshotRef, stream: ResourceId, position: VersionId) -> Self {
        Self {
            snapshot,
            stream,
            position,
        }
    }
    pub fn snapshot(&self) -> &SnapshotRef {
        &self.snapshot
    }
    pub fn stream(&self) -> &ResourceId {
        &self.stream
    }
    pub fn position(&self) -> &VersionId {
        &self.position
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageSize(usize);
impl PageSize {
    pub fn new(n: usize) -> Result<Self> {
        if n == 0 || n > 100_000 {
            return Err(Error::invalid("page size 1..100000"));
        }
        Ok(Self(n))
    }
    pub fn get(self) -> usize {
        self.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    items: Vec<T>,
    snapshot: SnapshotRef,
    next: Option<PageCursor>,
}
impl<T> Page<T> {
    pub fn new(
        items: Vec<T>,
        snapshot: SnapshotRef,
        next: Option<PageCursor>,
        size: PageSize,
    ) -> Result<Self> {
        if items.len() > size.get()
            || next.as_ref().is_some_and(|c| c.snapshot() != &snapshot)
            || items.is_empty() && next.is_some()
        {
            return Err(Error::invalid("invalid bounded page"));
        }
        Ok(Self {
            items,
            snapshot,
            next,
        })
    }
    pub fn items(&self) -> &[T] {
        &self.items
    }
    pub fn into_items(self) -> Vec<T> {
        self.items
    }
    pub fn snapshot(&self) -> &SnapshotRef {
        &self.snapshot
    }
    pub fn next(&self) -> Option<&PageCursor> {
        self.next.as_ref()
    }
    pub fn complete(&self) -> bool {
        self.next.is_none()
    }
}
/// Cumulative page validation. finish is mandatory; empty terminal pages are valid.
pub struct PageTracker {
    snapshot: SnapshotRef,
    stream: ResourceId,
    seen: std::collections::BTreeSet<VersionId>,
    expected: Option<PageCursor>,
    count: usize,
    max: usize,
    complete: bool,
}
impl PageTracker {
    pub fn new(snapshot: SnapshotRef, stream: ResourceId, max: usize) -> Self {
        Self {
            snapshot,
            stream,
            seen: Default::default(),
            expected: None,
            count: 0,
            max,
            complete: false,
        }
    }
    pub fn accept<T>(&mut self, request: Option<&PageCursor>, page: &Page<T>) -> Result<()> {
        if self.complete || request != self.expected.as_ref() || page.snapshot() != &self.snapshot {
            return Err(Error::invalid("page sequence/snapshot"));
        }
        let count = self
            .count
            .checked_add(page.items.len())
            .ok_or_else(Error::limit)?;
        if count > self.max {
            return Err(Error::limit());
        }
        if let Some(c) = page.next() {
            if c.stream() != &self.stream || !self.seen.insert(c.position.clone()) {
                return Err(Error::invalid("nonprogress cursor"));
            }
        }
        self.count = count;
        self.expected = page.next.clone();
        self.complete = page.complete();
        Ok(())
    }
    pub fn finish(self) -> Result<usize> {
        if !self.complete {
            return Err(Error::invalid("incomplete export"));
        }
        Ok(self.count)
    }
}
