use super::{controller::DependencyFootprint, property_iri, Work};
use cdb_core::{
    admission::{DependencyRecord, ExportRecord},
    claim::*,
    contracts::*,
    id::*,
    snapshot::*,
    CanonicalValue as V, Error, Result, Timestamp,
};
use std::collections::BTreeSet;

pub(super) struct Guard<'a, 'w, P: PolicyService> {
    pub view: &'a dyn RawQueryView,
    pub policy: &'a P,
    pub context: &'a P::Context,
    pub cutoff: Timestamp,
    pub mappings: Option<&'a dyn super::MappedFieldProvider>,
    pub ontology: Option<&'a dyn super::OntologyProvider>,
    pub work: &'w mut Work<'a>,
    pub dependencies: DependencyFootprint,
}
#[derive(Clone)]
pub(super) struct Usable {
    pub claim: AdmittedClaim,
    pub state: LifecycleState,
    pub supports: Vec<ClaimId>,
    pub dependencies: DependencyFootprint,
}
impl<P: PolicyService> Guard<'_, '_, P> {
    pub fn reset_dependencies(&mut self) {
        self.dependencies = DependencyFootprint::default();
    }
    pub fn take_dependencies(&mut self) -> DependencyFootprint {
        std::mem::take(&mut self.dependencies)
    }
    fn resource_allowed(&mut self, resource: &ResourceId) -> Result<bool> {
        let allowed = self.policy.resource_allowed(self.context, resource)?;
        if allowed {
            self.dependencies.insert_resource(resource.clone());
        }
        Ok(allowed)
    }
    fn fact_allowed(&mut self, resource: &ResourceId, property: &Iri) -> Result<bool> {
        let allowed = self.policy.fact_allowed(self.context, resource, property)?;
        if allowed {
            self.dependencies
                .insert_fact(resource.clone(), property.clone());
        }
        Ok(allowed)
    }
    pub fn mapped(
        &mut self,
        claim: &ClaimId,
        mapping: &crate::compiler::StoredPredicateMapping,
        field: &crate::compiler::FieldRef,
    ) -> Result<crate::values::Value> {
        self.work.tick(1)?;
        let resolver = self.mappings.ok_or_else(|| {
            Error::new(
                cdb_core::ErrorKind::Unsupported,
                "mapped field provider unavailable",
            )
        })?;
        if resolver.identity() != self.view.identity() {
            return Err(Error::new(
                cdb_core::ErrorKind::Snapshot,
                "exact mapped field snapshot required",
            ));
        }
        if !resolver.supports(mapping) {
            return Err(Error::new(
                cdb_core::ErrorKind::Unsupported,
                "mapped field capability unavailable",
            ));
        }
        self.authorize_typed_dependencies(
            resolver.claim_dependencies(),
            resolver.artifact_dependencies(),
        )?;
        let dependencies = resolver.dependencies(claim, mapping)?;
        self.authorize_dependencies(dependencies, "mapped interpretation unavailable")?;
        self.work.tick(1)?;
        match resolver.value(claim, mapping)? {
            Some(value) => {
                self.work.retain(value)?;
                field.value(cdb_core::Lookup::Present(value))
            }
            None => Ok(crate::values::Value::Missing),
        }
    }
    pub fn ontology(
        &mut self,
        kind: super::OntologyKind,
        actual: &str,
        target: &str,
    ) -> Result<bool> {
        self.work.tick(1)?;
        let provider = self.ontology.ok_or_else(|| {
            Error::new(
                cdb_core::ErrorKind::Unsupported,
                "ontology provider unavailable",
            )
        })?;
        self.authorize_typed_dependencies(
            provider.claim_dependencies(),
            provider.artifact_dependencies(),
        )?;
        let dependencies = provider.dependencies(kind, actual, target)?;
        self.authorize_dependencies(dependencies, "ontology interpretation unavailable")?;
        self.work.tick(1)?;
        provider.entails(kind, actual, target)
    }
    fn authorize_typed_dependencies(
        &mut self,
        claims: &[ClaimId],
        artifacts: &[cdb_core::artifact::ArtifactRef],
    ) -> Result<()> {
        if claims.len().saturating_add(artifacts.len()) > self.work.options.max_records {
            return Err(Error::limit());
        }
        for id in claims {
            self.work.tick(1)?;
            let claim = self.view.claim(id)?.ok_or_else(|| {
                Error::new(
                    cdb_core::ErrorKind::NotFound,
                    "interpretation claim unavailable",
                )
            })?;
            // Authorize the immutable assertion even when it establishes a negative
            // via lifecycle selection. Do not reinterpret it as a resource record.
            if !self.base(&claim, false)? {
                return Err(Error::new(
                    cdb_core::ErrorKind::Denied,
                    "interpretation claim unavailable",
                ));
            }
        }
        for artifact in artifacts {
            let resource = ResourceId::new(artifact.iri().as_str())?;
            self.work.tick(1)?;
            if !self.resource_allowed(&resource)? {
                return Err(Error::new(
                    cdb_core::ErrorKind::Denied,
                    "interpretation artifact unavailable",
                ));
            }
            for key in ["iri", "version", "hash"] {
                self.work.tick(1)?;
                if !self.fact_allowed(&resource, &property_iri(&format!("artifact.{key}"))?)? {
                    return Err(Error::new(
                        cdb_core::ErrorKind::Denied,
                        "interpretation artifact unavailable",
                    ));
                }
            }
        }
        Ok(())
    }
    fn authorize_dependencies(
        &mut self,
        dependencies: &[super::MappingDependency],
        message: &'static str,
    ) -> Result<()> {
        if dependencies.is_empty() {
            return Err(Error::invalid("interpretation dependencies required"));
        }
        if dependencies.len() > self.work.options.max_records {
            return Err(Error::limit());
        }
        for dependency in dependencies {
            self.work.tick(1)?;
            if dependency.facts.len() > self.work.options.max_records {
                return Err(Error::limit());
            }
            if !self.resource(&dependency.resource)? {
                return Err(Error::new(cdb_core::ErrorKind::Denied, message));
            }
            let record = self
                .view
                .resource(&dependency.resource)?
                .ok_or_else(|| Error::new(cdb_core::ErrorKind::NotFound, message))?;
            for fact in &dependency.facts {
                self.work.tick(
                    record
                        .facts()
                        .len()
                        .checked_add(1)
                        .ok_or_else(Error::limit)?,
                )?;
                if !record.facts().iter().any(|f| f.predicate() == fact)
                    || !self.fact_allowed(&dependency.resource, fact)?
                {
                    return Err(Error::new(cdb_core::ErrorKind::Denied, message));
                }
            }
        }
        Ok(())
    }
    fn record(&mut self, record: &DependencyRecord) -> Result<bool> {
        self.work.tick(1)?;
        // Protected run envelopes (including legacy summaries) are not graph
        // interpretation, labels, or source descriptors, even for administrators.
        if record.kind() == cdb_core::admission::ResourceKind::RunDescriptor {
            return Ok(false);
        }
        if !self.resource_allowed(record.id())? {
            return Ok(false);
        }
        let mut allowed = true;
        for fact in record.facts() {
            self.work.tick(1)?;
            allowed &= self.fact_allowed(record.id(), fact.predicate())?;
        }
        Ok(allowed)
    }
    pub fn resource(&mut self, id: &ResourceId) -> Result<bool> {
        self.work.tick(1)?;
        let Some(record) = self.view.resource(id)? else {
            return Ok(false);
        };
        self.work.retain(&record.projection())?;
        self.record(&record)
    }
    pub fn entity(&mut self, id: &EntityId) -> Result<bool> {
        self.work.tick(1)?;
        let Some(records) = self.view.entity(id)? else {
            return Ok(false);
        };
        if records.len() > self.work.options.max_records {
            return Err(Error::limit());
        }
        if records.is_empty() {
            return Ok(false);
        }
        let mut allowed = true;
        for record in records {
            self.work.retain(&record.projection())?;
            allowed &= self.record(&record)?;
        }
        Ok(allowed)
    }
    fn properties(&mut self, id: &ResourceId, value: &V, path: &str) -> Result<bool> {
        self.work.tick(1)?;
        let mut allowed = self.fact_allowed(id, &property_iri(path)?)?;
        match value {
            V::Object(o) => {
                for (k, v) in o {
                    allowed &= self.properties(id, v, &format!("{path}.{k}"))?;
                }
            }
            V::Array(a) => {
                for v in a {
                    allowed &= self.properties(id, v, path)?;
                }
            }
            _ => {}
        }
        Ok(allowed)
    }
    // Does NOT recursively follow arbitrary business references or evaluate support lifecycle.
    fn base(&mut self, claim: &AdmittedClaim, endpoints: bool) -> Result<bool> {
        self.work.tick(1)?;
        if claim.transaction_time() > self.cutoff {
            return Ok(false);
        }
        let response = claim.response(LifecycleState::Active);
        self.work.retain(&response)?;
        // E0 has already performed complete same-ledger claim authorization,
        // including metadata and lifecycle support visibility. Classification
        // v2 nevertheless names separately protected established support, so
        // require that support in this exact prepared view before the early
        // return. The metadata is never itself an authorization grant.
        if self.view.claim_is_pre_authorized(claim.id()) {
            if let Some(classification) = claim.candidate().classification_metadata()? {
                for support in classification.established_supports() {
                    let support_claim = ClaimId::new(support.as_str())?;
                    if !self.view.claim_is_pre_authorized(&support_claim)
                        && !self.resource(support)?
                    {
                        return Ok(false);
                    }
                }
            }
            return Ok(true);
        }
        let id = ResourceId::new(claim.id().as_str())?;
        if !self.resource_allowed(&id)? {
            return Ok(false);
        }
        let mut allowed = true;
        for (k, v) in response.field("meta")?.as_object()? {
            allowed &= self.properties(&id, v, k)?;
        }
        let c = claim.candidate();
        if endpoints {
            allowed &= self.entity(c.subject())?;
            if let ClaimObject::Entity(e) = c.object() {
                allowed &= self.entity(e)?;
            }
        }
        let classification = c.classification_metadata()?;
        for iri in [
            c.relation(),
            c.relation_type(),
            c.subject_type(),
            c.object_type(),
            c.claim_type(),
        ]
        .into_iter()
        .chain(
            classification
                .iter()
                .flat_map(|metadata| {
                    metadata
                        .subject()
                        .classes()
                        .iter()
                        .chain(metadata.object().classes())
                })
                .map(|entry| entry.iri()),
        ) {
            // Vocabulary IRIs are external symbols. If the fixture supplies interpretation
            // records, their facts are required; absence is not an invented ontology closure.
            let rid = ResourceId::new(iri.as_str())?;
            self.work.tick(1)?;
            if let Some(r) = self.view.resource(&rid)? {
                allowed &= self.record(&r)?;
            }
        }
        if let Some(classification) = classification {
            for support in classification.established_supports() {
                let support_claim = ClaimId::new(support.as_str())?;
                allowed &=
                    self.view.claim_is_pre_authorized(&support_claim) || self.resource(support)?;
            }
        }
        for source in c.lineage().sources() {
            allowed &= self.resource(&ResourceId::new(source.id().as_str())?)?;
        }
        Ok(allowed)
    }
    pub fn usable(&mut self, claim: AdmittedClaim) -> Result<Option<Usable>> {
        self.reset_dependencies();
        // Enumerate raw support BEFORE filtering permissions: denied support poisons the
        // dependent candidate rather than disappearing into an incorrect active state.
        let supports = self.pages(|v, size, cursor| v.lifecycle(claim.id(), size, cursor))?;
        for record in &supports {
            let Some(support) = record.claim() else {
                return Err(Error::invalid("lifecycle stream record"));
            };
            self.work
                .retain(&support.response(LifecycleState::Active))?;
        }
        if !self.base(&claim, !claim.candidate().is_lifecycle_assertion())? {
            return Ok(None);
        }
        let mut visible = vec![];
        for record in supports {
            let ExportRecord::Lifecycle {
                assertion,
                transaction_time,
            } = record
            else {
                return Err(Error::invalid("lifecycle stream record"));
            };
            if assertion.target() != claim.id() {
                return Err(Error::invalid("lifecycle stream target"));
            }
            if transaction_time > self.cutoff {
                continue;
            }
            let support = AdmittedClaim::assign(assertion.candidate().clone(), transaction_time);
            if !self.base(&support, false)? {
                return Ok(None);
            }
            if !self.references(&assertion)? {
                return Ok(None);
            }
            let priority = match assertion.candidate().relation().as_str() {
                "ctxql:retracted_by" => 3,
                "ctxql:superseded_by" => 2,
                "ctxql:contradicted_by" => 1,
                _ => return Err(Error::invalid("lifecycle relation")),
            };
            visible.push((priority, transaction_time, assertion.id().clone()));
        }
        if claim.candidate().is_lifecycle_assertion()
            && !self.references(&LifecycleAssertion::new(claim.candidate().clone())?)?
        {
            return Ok(None);
        }
        visible.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)).then(a.2.cmp(&b.2)));
        let priority = visible.first().map_or(0, |s| s.0);
        let state = match priority {
            3 => LifecycleState::Retracted,
            2 => LifecycleState::Superseded,
            1 => LifecycleState::Contradicted,
            _ => LifecycleState::Active,
        };
        let supports = visible
            .into_iter()
            .filter(|s| s.0 == priority)
            .map(|s| s.2)
            .collect();
        let dependencies = self.take_dependencies();
        Ok(Some(Usable {
            claim,
            state,
            supports,
            dependencies,
        }))
    }
    fn references(&mut self, a: &LifecycleAssertion) -> Result<bool> {
        let mut allowed = true;
        for id in std::iter::once(a.target()).chain(a.referenced_claim()) {
            self.work.tick(1)?;
            let Some(c) = self.view.claim(id)? else {
                return Ok(false);
            };
            allowed &= self.base(&c, !c.candidate().is_lifecycle_assertion())?;
        }
        if let Some(id) = a.event() {
            allowed &= self.resource(id)?;
        }
        Ok(allowed)
    }
    pub fn pages<T>(
        &mut self,
        read: impl Fn(&dyn RawQueryView, PageSize, Option<&PageCursor>) -> Result<Page<T>>,
    ) -> Result<Vec<T>> {
        let mut cursor: Option<PageCursor> = None;
        let mut seen = BTreeSet::new();
        let mut out = vec![];
        loop {
            self.work.tick(1)?;
            let page = read(self.view, self.work.options.page_size, cursor.as_ref())?;
            if page.snapshot() != self.view.identity()
                || page.items().len() > self.work.options.page_size.get()
            {
                return Err(Error::invalid("page identity or size"));
            }
            self.work.tick(page.items().len())?;
            if out
                .len()
                .checked_add(page.items().len())
                .ok_or_else(Error::limit)?
                > self.work.options.max_records
            {
                return Err(Error::limit());
            }
            let next = page.next().cloned();
            if let Some(n) = &next {
                if page.items().is_empty()
                    || n.snapshot() != self.view.identity()
                    || cursor.as_ref().is_some_and(|c| c.stream() != n.stream())
                    || !seen.insert(n.position().clone())
                {
                    return Err(Error::invalid("page progress"));
                }
            }
            out.extend(page.into_items());
            cursor = next;
            if cursor.is_none() {
                break;
            }
        }
        Ok(out)
    }
}
