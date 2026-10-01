//! Local immutable adapter over an E0-authorized, C0-reasoned semantic view.
//! It retains no Fluree or sandbox handle and performs no graph I/O.

use cdb_backend_fluree::{
    reasoning_sandbox::PreparedOntology,
    semantic_policy::{SemanticPolicyBasis, SemanticPolicyMode},
    semantic_preparation::PreparedAuthorizedView,
};
use cdb_core::{
    artifact::ArtifactRef,
    contracts::{CapturedSnapshot, Direction, IoFuture, PreparedOntologyDescriptor, RawQueryView},
    id::{ClaimId, ContentHash, EntityId, Iri, PrincipalId, ResourceId, VersionId},
    recording::INTERPRETATION_SCOPE,
    recording_v4::{
        PreparedSemanticMappingDescriptor, SemanticEvidenceV4, SemanticEvidenceV4Input,
        SemanticPolicyModeV4, SupportedSubsetEvidenceV4,
    },
    snapshot::{Page, PageCursor, PageSize, SnapshotRef},
    CanonicalValue as V, Error, ErrorKind, Limits, Result, Timestamp,
};
pub const SEMANTIC_COUNT_RESOLVER: &[u8] = b"ctxql-local-count/v1";

const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const RDF_LANG_STRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";
const COMMONS_TEXTUAL_NAME: &str = "https://www.omg.org/spec/Commons/Designators/hasTextualName";

use cdb_engine::{
    compiler::FieldMapping,
    execution::{
        ExecutionOptions, LandingCatalog, LandingEntry, LocalPredicateRuntime, MappedFieldProvider,
        MappingDependency, OntologyKind, OntologyProvider, PreparedView, ViewProvider,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthorizedLabel {
    pub value: String,
    pub dependencies: Vec<String>,
}

pub struct SemanticInterpretation {
    identity: SnapshotRef,
    descriptor: PreparedOntologyDescriptor,
    ontology: Option<PreparedOntology>,
    policy_basis: SemanticPolicyBasis,
    evidence: SemanticEvidenceV4,
    dependencies: Vec<MappingDependency>,
    mappings: std::collections::BTreeMap<String, FieldMapping>,
    mapped_values: std::collections::BTreeMap<(ClaimId, String), V>,
    mapping_artifacts: Vec<ArtifactRef>,
    mapping_descriptor: PreparedSemanticMappingDescriptor,
    control_resources:
        std::collections::BTreeMap<ResourceId, cdb_core::admission::DependencyRecord>,
    visible_supports: std::collections::BTreeSet<ClaimId>,
    landing_entries: Vec<LandingEntry>,
}

impl SemanticInterpretation {
    /// Only identifiers from the prepared authorized catalog; the engine still
    /// evaluates claim authorization, lifecycle and all execution bounds.
    pub(crate) fn inventory_seeds(&self) -> Vec<String> {
        self.landing_entries
            .iter()
            .map(|entry| entry.id.as_str().to_owned())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn new(
        captured: &CapturedSnapshot,
        authorized: PreparedAuthorizedView,
        ontology: PreparedOntology,
    ) -> Result<Self> {
        Self::from_parts(captured, authorized, Some(ontology), Vec::new(), Vec::new())
    }

    pub fn new_mapped(
        captured: &CapturedSnapshot,
        authorized: PreparedAuthorizedView,
        ontology: PreparedOntology,
        mappings: Vec<FieldMapping>,
        artifacts: Vec<ArtifactRef>,
    ) -> Result<Self> {
        Self::from_parts(captured, authorized, Some(ontology), mappings, artifacts)
    }

    /// Freeze E0 authorization evidence without constructing a reasoning sandbox.
    /// Ordinary traversal still consumes the authorized support selection, while
    /// the descriptor explicitly records that no materialization or reasoning ran.
    pub fn new_authorized(
        captured: &CapturedSnapshot,
        authorized: PreparedAuthorizedView,
    ) -> Result<Self> {
        Self::from_parts(captured, authorized, None, Vec::new(), Vec::new())
    }

    pub fn new_authorized_mapped(
        captured: &CapturedSnapshot,
        authorized: PreparedAuthorizedView,
        mappings: Vec<FieldMapping>,
        artifacts: Vec<ArtifactRef>,
    ) -> Result<Self> {
        Self::from_parts(captured, authorized, None, mappings, artifacts)
    }

    fn from_parts(
        captured: &CapturedSnapshot,
        authorized: PreparedAuthorizedView,
        ontology: Option<PreparedOntology>,
        mappings: Vec<FieldMapping>,
        artifacts: Vec<ArtifactRef>,
    ) -> Result<Self> {
        let manifest_identity = &authorized.manifest.capture;
        if manifest_identity.ledger != captured.snapshot.pin().graph().as_str()
            || manifest_identity.commit_cid != captured.snapshot.pin().receipt().as_str()
            || manifest_identity.t.to_string() != captured.snapshot.pin().revision().as_str()
        {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "exact semantic preparation capture required",
            ));
        }
        if authorized.manifest.supported_subset.is_some() && ontology.is_none() {
            return Err(Error::invalid(
                "supported subset evidence requires prepared ontology",
            ));
        }
        let descriptor = match &ontology {
            Some(ontology) => {
                ontology.descriptor(captured.snapshot.clone(), &authorized.manifest)?
            }
            None => PreparedOntologyDescriptor::no_sandbox(
                captured.snapshot.clone(),
                authorized.manifest.authorized_premise_root.0.clone(),
                authorized.manifest.execution_manifest_root.0.clone(),
                ContentHash::of_bytes(authorized.manifest.protected_completeness.as_bytes()),
            )?,
        };
        let (mappings, mapped_values, mapping_artifacts, mapping_descriptor, dependencies) =
            prepare_mappings(
                captured,
                &authorized,
                ontology.as_ref(),
                mappings,
                artifacts,
                &descriptor,
            )?;
        let requested_as_of = if authorized
            .manifest
            .capture
            .requested_as_of
            .starts_with("t:")
        {
            None
        } else {
            Some(Timestamp::parse(
                &authorized.manifest.capture.requested_as_of,
            )?)
        };
        let visible_supports = authorized
            .manifest
            .visible_supports
            .iter()
            .map(ClaimId::new)
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        let landing_entries = semantic_landing_entries(&authorized.authorized_claims)?;
        let supported_subset = authorized
            .manifest
            .supported_subset
            .as_ref()
            .map(|manifest| {
                let input = manifest.recording_input(Limits::default())?;
                SupportedSubsetEvidenceV4::new(input, Limits::default())
            })
            .transpose()?;
        let evidence = SemanticEvidenceV4::new(
            SemanticEvidenceV4Input {
                capture: captured.snapshot.clone(),
                requested_as_of,
                policy_mode: match authorized.policy_basis.mode {
                    SemanticPolicyMode::Unrestricted => SemanticPolicyModeV4::Unrestricted,
                    SemanticPolicyMode::Configured => SemanticPolicyModeV4::Configured,
                },
                policy_dependency_root: authorized.policy_basis.dependency_root.clone(),
                policy_source_observation: ResourceId::new(
                    &authorized.policy_basis.source_observation,
                )?,
                principal: PrincipalId::new(&authorized.policy_basis.principal)?,
                action: Iri::new(&authorized.policy_basis.action)?,
                historical_config_root: authorized.manifest.historical_config_root.clone(),
                graph_role_map_root: authorized.graph_role_map_root,
                configuration_graph: Iri::new(&authorized.configuration_graph)?,
                governed_data_graphs: authorized
                    .governed_data_graphs
                    .iter()
                    .map(Iri::new)
                    .collect::<Result<Vec<_>>>()?,
                claim_graphs: authorized
                    .claim_graphs
                    .iter()
                    .map(Iri::new)
                    .collect::<Result<Vec<_>>>()?,
                schema_source: Iri::new(&authorized.manifest.reasoning.schema_source)?,
                schema_graphs: authorized
                    .manifest
                    .reasoning
                    .schema_graphs
                    .iter()
                    .map(Iri::new)
                    .collect::<Result<Vec<_>>>()?,
                follow_owl_imports: authorized.manifest.reasoning.follow_owl_imports,
                data_root: authorized.manifest.data_root.clone(),
                schema_root: authorized.manifest.schema_root.clone(),
                data_commitments: authorized
                    .manifest
                    .data_quads
                    .iter()
                    .map(|quad| quad.commitment_hash())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                schema_commitments: authorized
                    .manifest
                    .schema_quads
                    .iter()
                    .map(|quad| quad.commitment_hash())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                visible_support_ids: authorized
                    .manifest
                    .visible_supports
                    .iter()
                    .map(Iri::new)
                    .collect::<Result<Vec<_>>>()?,
                authorized_data_quads: u64::try_from(
                    authorized.manifest.authorized_counts.data_quads,
                )
                .map_err(|_| Error::limit())?,
                authorized_schema_quads: u64::try_from(
                    authorized.manifest.authorized_counts.schema_quads,
                )
                .map_err(|_| Error::limit())?,
                visible_supports: u64::try_from(
                    authorized.manifest.authorized_counts.visible_supports,
                )
                .map_err(|_| Error::limit())?,
                authorized_premise_root: authorized.manifest.authorized_premise_root.0.clone(),
                execution_manifest_root: authorized.manifest.execution_manifest_root.0.clone(),
                ontology_profile: VersionId::new(
                    authorized.manifest.ontology_profile.identity.clone(),
                )?,
                full_ontology_bundle_root: authorized
                    .manifest
                    .ontology_profile
                    .full_bundle_root
                    .clone(),
                ontology_profile_result_root: authorized
                    .manifest
                    .ontology_profile
                    .result_root
                    .clone(),
                reasoner_input_root: authorized.manifest.reasoner_input_root.clone(),
                structural_mapping_algorithm: VersionId::new(
                    authorized.manifest.structural_mapping_algorithm.clone(),
                )?,
                profile_limits_identity: authorized.manifest.profile_limits_identity.clone(),
                materialization_limits_identity: descriptor.materialization_limits_identity.clone(),
                reasoning_limits_identity: descriptor.reasoning_limits_identity.clone(),
                prepared_root: descriptor.prepared_root.clone(),
                semantic_codec: cdb_core::id::VersionId::new("ctxql-semantic-rdf/v1")?,
                commitment_algorithm: cdb_core::id::VersionId::new(
                    "ctxql-source-quad-commitment/sha256-v2",
                )?,
                extraction_algorithm: cdb_core::id::VersionId::new(
                    "ctxql-authorized-view-extraction/v2",
                )?,
                materializer: descriptor.materializer.clone(),
                reasoner: descriptor.reasoner.clone(),
                budget_identity: descriptor.budget_identity.clone(),
                diagnostics_root: descriptor.diagnostics_root.clone(),
                completeness_selector: authorized.manifest.protected_completeness.clone(),
                completeness_evidence: descriptor.completeness_root.clone(),
                mapping: mapping_descriptor.clone(),
                supported_subset,
            },
            Limits::default(),
        )?;
        Ok(Self {
            identity: captured.snapshot.clone(),
            descriptor,
            ontology,
            policy_basis: authorized.policy_basis,
            evidence,
            dependencies,
            mappings,
            mapped_values,
            mapping_artifacts,
            mapping_descriptor,
            control_resources: std::collections::BTreeMap::new(),
            visible_supports,
            landing_entries,
        })
    }

    pub(crate) fn label_dependencies(&self, id: &str) -> Vec<String> {
        self.labels_for(id)
            .into_iter()
            .flat_map(|label| label.dependencies)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Labels are exposed only from the already-authorized landing catalog and
    /// retain the exact support claims needed to disclose them.
    pub(crate) fn labels_for(&self, id: &str) -> Vec<AuthorizedLabel> {
        self.landing_entries
            .iter()
            .filter(|entry| entry.id.as_str() == id)
            .filter_map(|entry| {
                entry.label.as_ref().map(|label| AuthorizedLabel {
                    value: label.clone(),
                    dependencies: entry
                        .dependencies
                        .iter()
                        .map(|id| id.as_str().to_owned())
                        .collect(),
                })
            })
            .collect()
    }

    pub fn with_control_resources(
        mut self,
        resources: impl IntoIterator<Item = cdb_core::admission::DependencyRecord>,
    ) -> Self {
        self.control_resources = resources
            .into_iter()
            .map(|record| (record.id().clone(), record))
            .collect();
        self
    }

    pub fn policy_basis(&self) -> &SemanticPolicyBasis {
        &self.policy_basis
    }

    pub fn recording_evidence(&self) -> &SemanticEvidenceV4 {
        &self.evidence
    }

    pub fn mapping_descriptor(&self) -> &PreparedSemanticMappingDescriptor {
        &self.mapping_descriptor
    }
}

/// Build the semantic landing catalog exclusively from the already-authorized
/// proposition export. Every visible entity retains an identifier-only entry;
/// conventional name claims add lexical entries bound to their exact support.
pub(crate) fn semantic_landing_entries(
    records: &[cdb_core::admission::ExportRecord],
) -> Result<Vec<LandingEntry>> {
    use crate::entity_lookup::{RDFS_LABEL, SKOS_ALT_LABEL, SKOS_PREF_LABEL};
    use cdb_core::claim::ClaimObject;

    let mut entities = std::collections::BTreeSet::new();
    let mut labels = Vec::new();
    for record in records {
        let cdb_core::admission::ExportRecord::Claim(claim) = record else {
            continue;
        };
        let candidate = claim.candidate();
        if candidate.is_lifecycle_assertion() {
            continue;
        }
        entities.insert(candidate.subject().clone());
        if let ClaimObject::Entity(entity) = candidate.object() {
            entities.insert(entity.clone());
        }

        if !matches!(
            candidate.relation().as_str(),
            RDFS_LABEL | SKOS_PREF_LABEL | SKOS_ALT_LABEL | COMMONS_TEXTUAL_NAME
        ) {
            continue;
        }
        let ClaimObject::Literal(literal) = candidate.object() else {
            continue;
        };
        if !matches!(literal.datatype().as_str(), XSD_STRING | RDF_LANG_STRING) {
            continue;
        }
        // CandidateClaim construction has already validated datatype/language
        // consistency. Requiring a canonical string here excludes non-text
        // values without introducing additional label normalization semantics.
        let Ok(label) = literal.value().as_str() else {
            continue;
        };
        labels.push(LandingEntry {
            id: candidate.subject().clone(),
            label: Some(label.to_owned()),
            dependencies: vec![ResourceId::new(claim.id().as_str())?],
        });
    }

    let mut entries = entities
        .into_iter()
        .map(|id| LandingEntry {
            id,
            label: None,
            dependencies: Vec::new(),
        })
        .collect::<Vec<_>>();
    entries.extend(labels);
    Ok(entries)
}

pub fn mappings_from_config(config: &V) -> Result<Vec<FieldMapping>> {
    let mut mappings = Vec::new();
    for (field, value) in config.field("fields")?.as_object()? {
        let Some(source) = value.as_object()?.get("source") else {
            continue;
        };
        let iri = Iri::new(value.field("iri")?.as_str()?)?;
        let requires = value
            .as_object()?
            .get("requires")
            .map(|requires| {
                requires
                    .as_array()?
                    .iter()
                    .map(|item| Ok(item.as_str()?.to_owned()))
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        let mapping = match source.as_str()? {
            "stored_predicate" => FieldMapping::StoredPredicate {
                field: field.clone(),
                iri,
                requires,
            },
            "reasoned" => FieldMapping::Reasoned {
                field: field.clone(),
                iri,
                requires,
            },
            "computed" => FieldMapping::Computed {
                field: field.clone(),
                iri,
                resolver: ArtifactRef::from_value(value.field("resolver")?)?,
                requires,
            },
            _ => continue,
        };
        mappings.push(mapping);
    }
    Ok(mappings)
}

fn mapping_projection(mapping: &FieldMapping) -> V {
    let mut fields = std::collections::BTreeMap::from([
        ("field".into(), V::string(mapping.field())),
        ("source".into(), V::string(mapping.source())),
        ("iri".into(), V::string(mapping.iri().as_str())),
        (
            "requires".into(),
            V::Array(mapping.requires().iter().map(V::string).collect()),
        ),
    ]);
    fields.insert(
        "resolver".into(),
        mapping.resolver().map_or(V::Null, ArtifactRef::projection),
    );
    V::Object(fields)
}

fn exact_value(term: &cdb_backend_fluree::authorized_view::ExactTerm) -> V {
    match term {
        cdb_backend_fluree::authorized_view::ExactTerm::Iri(value) => V::string(value),
        cdb_backend_fluree::authorized_view::ExactTerm::ScopedBlankNode(_) => {
            unreachable!("structural nodes are never public mapped values")
        }
        cdb_backend_fluree::authorized_view::ExactTerm::Literal {
            lexical,
            datatype,
            language,
        } => V::Object(std::collections::BTreeMap::from([
            ("kind".into(), V::string("literal")),
            ("datatype".into(), V::string(datatype)),
            ("value".into(), V::string(lexical)),
            (
                "language".into(),
                language.as_ref().map_or(V::Null, V::string),
            ),
        ])),
    }
}

fn canonical_root(label: &str, values: &[V]) -> Result<ContentHash> {
    let bytes = V::Array(values.to_vec()).canonical_bytes(Limits::default())?;
    let mut framed = Vec::with_capacity(label.len() + 1 + bytes.len());
    framed.extend_from_slice(label.as_bytes());
    framed.push(0);
    framed.extend_from_slice(&bytes);
    Ok(ContentHash::of_bytes(&framed))
}

type PreparedMappings = (
    std::collections::BTreeMap<String, FieldMapping>,
    std::collections::BTreeMap<(ClaimId, String), V>,
    Vec<ArtifactRef>,
    PreparedSemanticMappingDescriptor,
    Vec<MappingDependency>,
);

fn prepare_mappings(
    captured: &CapturedSnapshot,
    authorized: &PreparedAuthorizedView,
    ontology: Option<&PreparedOntology>,
    mappings: Vec<FieldMapping>,
    artifacts: Vec<ArtifactRef>,
    ontology_descriptor: &PreparedOntologyDescriptor,
) -> Result<PreparedMappings> {
    if mappings.is_empty() {
        return Ok((
            Default::default(),
            Default::default(),
            Vec::new(),
            PreparedSemanticMappingDescriptor::none(
                captured.snapshot.clone(),
                ontology_descriptor.prepared_root.clone(),
                Limits::default(),
            )?,
            vec![MappingDependency {
                resource: ResourceId::new(INTERPRETATION_SCOPE)?,
                facts: Vec::new(),
            }],
        ));
    }
    if mappings.len() > Limits::default().values() {
        return Err(Error::limit());
    }
    let mut by_name = std::collections::BTreeMap::new();
    for mapping in mappings {
        if by_name
            .insert(mapping.field().to_owned(), mapping)
            .is_some()
        {
            return Err(Error::invalid("duplicate semantic mapping field"));
        }
    }
    let definitions = by_name.values().map(mapping_projection).collect::<Vec<_>>();
    let definition_root = canonical_root("ctxql-semantic-mapping-definitions/v1", &definitions)?;

    let mut keyed_artifacts = artifacts
        .into_iter()
        .map(|artifact| {
            Ok((
                artifact.projection().canonical_bytes(Limits::default())?,
                artifact,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    keyed_artifacts.sort_by(|left, right| left.0.cmp(&right.0));
    keyed_artifacts.dedup_by(|left, right| left.0 == right.0);
    let artifacts = keyed_artifacts
        .into_iter()
        .map(|(_, artifact)| artifact)
        .collect::<Vec<_>>();
    let mut expected_resolvers = by_name
        .values()
        .filter_map(|mapping| mapping.resolver().cloned())
        .map(|artifact| {
            Ok((
                artifact.projection().canonical_bytes(Limits::default())?,
                artifact,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    expected_resolvers.sort_by(|left, right| left.0.cmp(&right.0));
    expected_resolvers.dedup_by(|left, right| left.0 == right.0);
    if expected_resolvers
        .into_iter()
        .map(|(_, artifact)| artifact)
        .collect::<Vec<_>>()
        != artifacts
    {
        return Err(Error::invalid("semantic mapping resolver binding"));
    }
    let resolver_values = artifacts
        .iter()
        .map(ArtifactRef::projection)
        .collect::<Vec<_>>();
    let resolver_root = canonical_root("ctxql-semantic-mapping-resolvers/v1", &resolver_values)?;

    let mut subjects = std::collections::BTreeMap::new();
    for record in &authorized.authorized_claims {
        if let Some(claim) = record.claim() {
            if authorized
                .manifest
                .visible_supports
                .contains(claim.id().as_str())
            {
                let subject = claim.candidate().subject().as_str().to_owned();
                if subjects
                    .insert(claim.id().clone(), subject.clone())
                    .is_some_and(|old| old != subject)
                {
                    return Err(Error::invalid("duplicate semantic mapping claim"));
                }
            }
        }
    }
    let mut mapped_values = std::collections::BTreeMap::new();
    for (claim, subject) in subjects {
        for mapping in by_name.values() {
            let mut values = authorized
                .manifest
                .data_quads
                .iter()
                .filter(|quad| quad.subject == subject && quad.predicate == mapping.iri().as_str())
                .map(|quad| exact_value(&quad.object))
                .collect::<Vec<_>>();
            if !matches!(mapping, FieldMapping::StoredPredicate { .. }) {
                let ontology = ontology.ok_or_else(|| {
                    Error::new(
                        ErrorKind::Unsupported,
                        "semantic mapping reasoning unavailable",
                    )
                })?;
                values.extend(
                    ontology
                        .inferred_facts
                        .iter()
                        .filter(|fact| {
                            fact.subject == subject && fact.predicate == mapping.iri().as_str()
                        })
                        .map(|fact| exact_value(&fact.object)),
                );
            }
            let mut keyed = values
                .into_iter()
                .map(|value| Ok((value.canonical_bytes(Limits::default())?, value)))
                .collect::<Result<Vec<_>>>()?;
            keyed.sort_by(|left, right| left.0.cmp(&right.0));
            keyed.dedup_by(|left, right| left.0 == right.0);
            if keyed.is_empty() {
                continue;
            }
            let value = if matches!(mapping, FieldMapping::Computed { .. }) {
                V::integer(u64::try_from(keyed.len()).map_err(|_| Error::limit())?)
            } else {
                V::Array(keyed.into_iter().map(|(_, value)| value).collect())
            };
            mapped_values.insert((claim.clone(), mapping.field().to_owned()), value);
        }
    }
    let value_projections = mapped_values
        .iter()
        .map(|((claim, field), value)| {
            V::Object(std::collections::BTreeMap::from([
                ("claim".into(), V::string(claim.as_str())),
                ("field".into(), V::string(field)),
                ("value".into(), value.clone()),
            ]))
        })
        .collect::<Vec<_>>();
    let value_root = canonical_root("ctxql-semantic-mapping-values/v1", &value_projections)?;
    let mut dependency_resources =
        std::collections::BTreeSet::from([ResourceId::new(INTERPRETATION_SCOPE)?]);
    for required in by_name.values().flat_map(FieldMapping::requires) {
        dependency_resources.insert(ResourceId::new(required)?);
    }
    let dependencies = dependency_resources
        .into_iter()
        .map(|resource| MappingDependency {
            resource,
            facts: Vec::new(),
        })
        .collect::<Vec<_>>();
    let mut dependency_values = vec![
        V::string(authorized.manifest.authorized_premise_root.0.as_str()),
        V::string(authorized.manifest.execution_manifest_root.0.as_str()),
        V::string(resolver_root.as_str()),
    ];
    dependency_values.extend(
        dependencies
            .iter()
            .map(|dependency| V::string(dependency.resource.as_str())),
    );
    let dependency_root =
        canonical_root("ctxql-semantic-mapping-dependencies/v1", &dependency_values)?;
    let descriptor = PreparedSemanticMappingDescriptor::new(
        captured.snapshot.clone(),
        VersionId::new("ctxql-historical-semantic-mapping/v1")?,
        definition_root,
        u64::try_from(by_name.len()).map_err(|_| Error::limit())?,
        resolver_root,
        u64::try_from(artifacts.len()).map_err(|_| Error::limit())?,
        value_root,
        u64::try_from(mapped_values.len()).map_err(|_| Error::limit())?,
        dependency_root,
        ontology_descriptor.prepared_root.clone(),
        Limits::default(),
    )?;
    Ok((by_name, mapped_values, artifacts, descriptor, dependencies))
}

impl MappedFieldProvider for SemanticInterpretation {
    fn artifact_dependencies(&self) -> &[ArtifactRef] {
        &self.mapping_artifacts
    }

    fn identity(&self) -> &SnapshotRef {
        &self.identity
    }

    fn supports(&self, mapping: &FieldMapping) -> bool {
        self.mappings.get(mapping.field()) == Some(mapping)
    }

    fn dependencies(&self, _: &ClaimId, _: &FieldMapping) -> Result<&[MappingDependency]> {
        Ok(&self.dependencies)
    }

    fn value(&self, claim: &ClaimId, mapping: &FieldMapping) -> Result<Option<&V>> {
        Ok(self
            .mapped_values
            .get(&(claim.clone(), mapping.field().to_owned())))
    }
}

impl OntologyProvider for SemanticInterpretation {
    fn identity(&self) -> &SnapshotRef {
        &self.identity
    }

    fn prepared_descriptor(&self) -> Option<&PreparedOntologyDescriptor> {
        Some(&self.descriptor)
    }

    fn supports(&self, _: OntologyKind) -> bool {
        self.ontology.is_some()
    }

    fn dependencies(&self, _: OntologyKind, _: &str, _: &str) -> Result<&[MappingDependency]> {
        Ok(&self.dependencies)
    }

    fn entails(&self, kind: OntologyKind, actual: &str, target: &str) -> Result<bool> {
        let ontology = self
            .ontology
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Unsupported, "ontology reasoning unavailable"))?;
        Ok(match kind {
            OntologyKind::Class => ontology.entails_class(actual, target),
            OntologyKind::Property => ontology.entails_property(actual, target),
        })
    }
}

pub struct SemanticProvider<'a> {
    base: &'a dyn ViewProvider,
    interpretation: &'a SemanticInterpretation,
}

impl<'a> SemanticProvider<'a> {
    pub fn new(base: &'a dyn ViewProvider, interpretation: &'a SemanticInterpretation) -> Self {
        Self {
            base,
            interpretation,
        }
    }
}

impl ViewProvider for SemanticProvider<'_> {
    fn controller_runtime(
        &self,
    ) -> Option<&dyn cdb_engine::execution::controller::ControllerRuntime> {
        self.base.controller_runtime()
    }

    fn local_predicates(&self) -> Option<LocalPredicateRuntime<'_>> {
        self.base.local_predicates()
    }

    fn propose_stale<'a>(
        &'a self,
        requested: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, Option<SnapshotRef>> {
        self.base.propose_stale(requested, options)
    }

    fn mapped_fields(&self) -> Option<&dyn MappedFieldProvider> {
        (!self.interpretation.mappings.is_empty())
            .then_some(self.interpretation as &dyn MappedFieldProvider)
    }

    fn ontology(&self) -> Option<&dyn OntologyProvider> {
        self.interpretation
            .ontology
            .as_ref()
            .map(|_| self.interpretation as &dyn OntologyProvider)
    }

    fn evidence_reader(&self) -> Option<&dyn cdb_core::contracts::SourceReader> {
        self.base.evidence_reader()
    }

    fn evidence_footprint(&self) -> Result<Vec<cdb_core::recording::PolicyObservation>> {
        self.base.evidence_footprint()
    }

    fn open<'a>(
        &'a self,
        captured: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        Box::pin(async move {
            let prepared = self.base.open(captured, options).await?;
            if self.interpretation.landing_entries.len() > options.max_records {
                return Err(Error::limit());
            }
            Ok(PreparedView {
                view: std::sync::Arc::new(AuthorizedSemanticView {
                    base: prepared.view,
                    control_resources: self.interpretation.control_resources.clone(),
                    visible_supports: self.interpretation.visible_supports.clone(),
                }),
                landing: std::sync::Arc::new(SemanticLandingCatalog {
                    identity: captured.snapshot.clone(),
                    entries: self.interpretation.landing_entries.clone(),
                }),
            })
        })
    }
}

struct SemanticLandingCatalog {
    identity: SnapshotRef,
    entries: Vec<LandingEntry>,
}

impl LandingCatalog for SemanticLandingCatalog {
    fn identity(&self) -> &SnapshotRef {
        &self.identity
    }

    fn entries(&self) -> &[LandingEntry] {
        &self.entries
    }

    fn entries_are_authorized(&self) -> bool {
        true
    }
}

struct AuthorizedSemanticView {
    base: std::sync::Arc<dyn RawQueryView>,
    control_resources:
        std::collections::BTreeMap<ResourceId, cdb_core::admission::DependencyRecord>,
    visible_supports: std::collections::BTreeSet<ClaimId>,
}

impl RawQueryView for AuthorizedSemanticView {
    fn identity(&self) -> &SnapshotRef {
        self.base.identity()
    }

    fn claim(&self, id: &ClaimId) -> Result<Option<cdb_core::claim::AdmittedClaim>> {
        if self.visible_supports.contains(id) {
            self.base.claim(id)
        } else {
            Ok(None)
        }
    }

    fn claim_is_pre_authorized(&self, id: &ClaimId) -> bool {
        self.visible_supports.contains(id)
    }

    fn entity(&self, id: &EntityId) -> Result<Option<Vec<cdb_core::admission::DependencyRecord>>> {
        self.base.entity(id)
    }

    fn incident(
        &self,
        id: &EntityId,
        direction: Direction,
        size: PageSize,
        cursor: Option<&PageCursor>,
    ) -> Result<Page<cdb_core::claim::AdmittedClaim>> {
        let mut next = cursor.cloned();
        loop {
            let page = self.base.incident(id, direction, size, next.as_ref())?;
            let snapshot = page.snapshot().clone();
            let following = page.next().cloned();
            let claims = page
                .into_items()
                .into_iter()
                .filter(|claim| self.visible_supports.contains(claim.id()))
                .collect::<Vec<_>>();
            if !claims.is_empty() || following.is_none() {
                return Page::new(claims, snapshot, following, size);
            }
            next = following;
        }
    }

    fn resource(&self, id: &ResourceId) -> Result<Option<cdb_core::admission::DependencyRecord>> {
        match self.control_resources.get(id) {
            Some(record) => Ok(Some(record.clone())),
            None => self.base.resource(id),
        }
    }

    fn lifecycle(
        &self,
        id: &ClaimId,
        size: PageSize,
        cursor: Option<&PageCursor>,
    ) -> Result<Page<cdb_core::admission::ExportRecord>> {
        const MAX_FILTERED_PAGES: usize = 10_000;
        const MAX_FILTERED_RECORDS: usize = 1_000_000;

        let mut next = cursor.cloned();
        if next
            .as_ref()
            .is_some_and(|cursor| cursor.snapshot() != self.base.identity())
        {
            return Err(cdb_core::Error::new(
                cdb_core::ErrorKind::Snapshot,
                "lifecycle cursor snapshot",
            ));
        }
        let mut stream = next.as_ref().map(|cursor| cursor.stream().clone());
        let mut seen: std::collections::BTreeSet<cdb_core::id::VersionId> = next
            .as_ref()
            .map(|cursor| [cursor.position().clone()].into_iter().collect())
            .unwrap_or_default();
        let mut records = 0usize;
        for _ in 0..MAX_FILTERED_PAGES {
            let page = self.base.lifecycle(id, size, next.as_ref())?;
            if page.snapshot() != self.base.identity() {
                return Err(cdb_core::Error::new(
                    cdb_core::ErrorKind::Snapshot,
                    "lifecycle page snapshot",
                ));
            }
            records = records
                .checked_add(page.items().len())
                .ok_or_else(cdb_core::Error::limit)?;
            if records > MAX_FILTERED_RECORDS {
                return Err(cdb_core::Error::limit());
            }
            let snapshot = page.snapshot().clone();
            let following = page.next().cloned();
            if let Some(following) = &following {
                if stream
                    .as_ref()
                    .is_some_and(|expected| following.stream() != expected)
                    || next.as_ref() == Some(following)
                    || !seen.insert(following.position().clone())
                {
                    return Err(cdb_core::Error::invalid("nonprogress lifecycle cursor"));
                }
                stream.get_or_insert_with(|| following.stream().clone());
            }
            let mut visible = Vec::new();
            for record in page.into_items() {
                let cdb_core::admission::ExportRecord::Lifecycle { assertion, .. } = &record else {
                    return Err(cdb_core::Error::invalid(
                        "non-lifecycle record in lifecycle page",
                    ));
                };
                if self.visible_supports.contains(assertion.id()) {
                    visible.push(record);
                }
            }
            if !visible.is_empty() || following.is_none() {
                return Page::new(visible, snapshot, following, size);
            }
            next = following;
        }
        Err(cdb_core::Error::limit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdb_core::{
        admission::ExportRecord,
        claim::{AdmittedClaim, CandidateClaim, LifecycleAssertion},
        id::{AuthorityId, BackendId, GraphId, VersionId},
        snapshot::GraphPin,
        CanonicalValue as V,
    };

    fn pin() -> SnapshotRef {
        SnapshotRef::new(
            BackendId::new("semantic").unwrap(),
            GraphPin::new(
                AuthorityId::new("semantic-authority").unwrap(),
                GraphId::new("semantic-graph").unwrap(),
                VersionId::new("3").unwrap(),
                ResourceId::new("semantic-cid").unwrap(),
            ),
        )
    }

    fn claim(id: &str, subject: &str, relation: &str, object: V) -> ExportRecord {
        let value = V::Object(std::collections::BTreeMap::from([
            ("claim_id".into(), V::string(id)),
            ("subject_id".into(), V::string(subject)),
            ("relation".into(), V::string(relation)),
            ("object_id".into(), object),
            ("relation_type".into(), V::string("urn:type:relation")),
            ("subject_type".into(), V::string("urn:type:subject")),
            ("object_type".into(), V::string("urn:type:object")),
            ("claim_type".into(), V::string("urn:type:claim")),
            (
                "confidence".into(),
                V::parse(b"1", Limits::default()).unwrap(),
            ),
            ("grounding_level".into(), V::string("claim_only")),
        ]));
        ExportRecord::Claim(Box::new(AdmittedClaim::assign(
            CandidateClaim::from_value(&value).unwrap(),
            Timestamp::parse("2026-09-16T00:00:00Z").unwrap(),
        )))
    }

    fn literal(value: &str, datatype: &str, language: Option<&str>) -> V {
        V::Object(std::collections::BTreeMap::from([
            ("kind".into(), V::string("literal")),
            ("datatype".into(), V::string(datatype)),
            ("value".into(), V::string(value)),
            ("language".into(), language.map_or(V::Null, V::string)),
        ]))
    }

    fn lifecycle(id: &str, target: &str, relation: &str, reference: &str) -> ExportRecord {
        let mut value = V::parse(
            br#"{"claim_id":"life","subject_id":"target","relation":"ctxql:contradicted_by","object_id":"reference","relation_type":"urn:relation-type","subject_type":"urn:subject-type","object_type":"urn:object-type","claim_type":"urn:claim-type","confidence":0.75,"grounding_level":"claim_only"}"#,
            Limits::default(),
        )
        .unwrap();
        let V::Object(fields) = &mut value else {
            unreachable!()
        };
        fields.insert("claim_id".into(), V::string(id));
        fields.insert("subject_id".into(), V::string(target));
        fields.insert("relation".into(), V::string(relation));
        fields.insert("object_id".into(), V::string(reference));
        ExportRecord::Lifecycle {
            assertion: LifecycleAssertion::new(CandidateClaim::from_value(&value).unwrap())
                .unwrap(),
            transaction_time: Timestamp::parse("2026-09-16T00:00:00Z").unwrap(),
        }
    }

    struct LifecycleView {
        identity: SnapshotRef,
        pages: Vec<Vec<ExportRecord>>,
    }

    impl RawQueryView for LifecycleView {
        fn identity(&self) -> &SnapshotRef {
            &self.identity
        }

        fn claim(&self, _: &ClaimId) -> Result<Option<AdmittedClaim>> {
            Ok(None)
        }

        fn entity(
            &self,
            _: &EntityId,
        ) -> Result<Option<Vec<cdb_core::admission::DependencyRecord>>> {
            Ok(None)
        }

        fn incident(
            &self,
            _: &EntityId,
            _: Direction,
            size: PageSize,
            _: Option<&PageCursor>,
        ) -> Result<Page<AdmittedClaim>> {
            Page::new(Vec::new(), self.identity.clone(), None, size)
        }

        fn resource(
            &self,
            _: &ResourceId,
        ) -> Result<Option<cdb_core::admission::DependencyRecord>> {
            Ok(None)
        }

        fn lifecycle(
            &self,
            _: &ClaimId,
            size: PageSize,
            cursor: Option<&PageCursor>,
        ) -> Result<Page<ExportRecord>> {
            let index = cursor
                .map(|cursor| cursor.position().as_str().parse::<usize>().unwrap())
                .unwrap_or(0);
            let next = (index + 1 < self.pages.len()).then(|| {
                PageCursor::new(
                    self.identity.clone(),
                    ResourceId::new("lifecycle:test").unwrap(),
                    VersionId::new((index + 1).to_string()).unwrap(),
                )
            });
            Page::new(self.pages[index].clone(), self.identity.clone(), next, size)
        }
    }

    #[test]
    fn semantic_landing_uses_only_authorized_text_label_claims_and_keeps_identities_distinct() {
        use crate::entity_lookup::{RDFS_LABEL, SKOS_ALT_LABEL, SKOS_PREF_LABEL};

        let records = vec![
            claim(
                "urn:claim:a-label-1",
                "urn:opaque:a",
                RDFS_LABEL,
                literal("Acme Holdings", XSD_STRING, None),
            ),
            claim(
                "urn:claim:a-label-2",
                "urn:opaque:a",
                SKOS_PREF_LABEL,
                literal("Acme Holdings", XSD_STRING, None),
            ),
            claim(
                "urn:claim:a-alt",
                "urn:opaque:a",
                SKOS_ALT_LABEL,
                literal("Acme", RDF_LANG_STRING, Some("en")),
            ),
            claim(
                "urn:claim:b-label",
                "urn:opaque:b",
                RDFS_LABEL,
                literal("Acme Holdings", XSD_STRING, None),
            ),
            claim(
                "urn:claim:commons-name",
                "urn:opaque:c",
                COMMONS_TEXTUAL_NAME,
                literal("Acme Commons Name", XSD_STRING, None),
            ),
            claim(
                "urn:claim:ordinary-text",
                "urn:opaque:c",
                "urn:predicate:description",
                literal("Acme Holdings", XSD_STRING, None),
            ),
            claim(
                "urn:claim:custom-label",
                "urn:opaque:c",
                RDFS_LABEL,
                literal("Not a supported string", "urn:datatype:text", None),
            ),
            claim(
                "urn:claim:edge",
                "urn:opaque:c",
                "urn:predicate:related",
                V::string("urn:opaque:object"),
            ),
            lifecycle(
                "urn:claim:lifecycle",
                "urn:hidden:lifecycle-subject",
                "ctxql:contradicted_by",
                "urn:hidden:lifecycle-object",
            ),
        ];

        let entries = semantic_landing_entries(&records).unwrap();
        let id_only = entries
            .iter()
            .filter(|entry| entry.label.is_none())
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            id_only,
            vec![
                "urn:opaque:a",
                "urn:opaque:b",
                "urn:opaque:c",
                "urn:opaque:object"
            ]
        );
        let labels = entries
            .iter()
            .filter_map(|entry| {
                entry.label.as_ref().map(|label| {
                    (
                        entry.id.as_str(),
                        label.as_str(),
                        entry.dependencies[0].as_str(),
                    )
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            labels,
            vec![
                ("urn:opaque:a", "Acme Holdings", "urn:claim:a-label-1"),
                ("urn:opaque:a", "Acme Holdings", "urn:claim:a-label-2"),
                ("urn:opaque:a", "Acme", "urn:claim:a-alt"),
                ("urn:opaque:b", "Acme Holdings", "urn:claim:b-label"),
                (
                    "urn:opaque:c",
                    "Acme Commons Name",
                    "urn:claim:commons-name"
                ),
            ]
        );
        assert!(entries
            .iter()
            .all(|entry| entry.label.as_deref() != Some("Not a supported string")));
        assert!(!entries
            .iter()
            .any(|entry| entry.id.as_str().starts_with("urn:hidden:")));
    }

    #[test]
    fn semantic_mapping_config_is_typed_without_native_selector() {
        let resolver = ArtifactRef::new(
            Iri::new("urn:resolver:count").unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(SEMANTIC_COUNT_RESOLVER),
        );
        let config = V::Object(std::collections::BTreeMap::from([(
            "fields".into(),
            V::Object(std::collections::BTreeMap::from([
                (
                    "meta:ext:stored".into(),
                    V::Object(std::collections::BTreeMap::from([
                        ("source".into(), V::string("stored_predicate")),
                        ("iri".into(), V::string("urn:p:stored")),
                    ])),
                ),
                (
                    "meta:ext:count".into(),
                    V::Object(std::collections::BTreeMap::from([
                        ("source".into(), V::string("computed")),
                        ("iri".into(), V::string("urn:p:count")),
                        ("resolver".into(), resolver.projection()),
                    ])),
                ),
            ])),
        )]));
        let mappings = mappings_from_config(&config).unwrap();
        assert_eq!(mappings.len(), 2);
        assert!(mappings.iter().any(|mapping| matches!(
            mapping,
            FieldMapping::StoredPredicate { iri, .. } if iri.as_str() == "urn:p:stored"
        )));
        assert!(mappings.iter().any(|mapping| matches!(
            mapping,
            FieldMapping::Computed { resolver: actual, .. } if actual == &resolver
        )));
    }

    #[test]
    fn semantic_mapping_exact_literal_retains_lexical_datatype_and_language() {
        let value = exact_value(&cdb_backend_fluree::authorized_view::ExactTerm::Literal {
            lexical: "colour".into(),
            datatype: "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString".into(),
            language: Some("en-GB".into()),
        });
        assert_eq!(value.field("kind").unwrap().as_str().unwrap(), "literal");
        assert_eq!(value.field("value").unwrap().as_str().unwrap(), "colour");
        assert_eq!(value.field("language").unwrap().as_str().unwrap(), "en-GB");
    }

    #[test]
    fn lifecycle_filters_on_lifecycle_claim_visibility_across_hidden_pages() {
        let identity = pin();
        let hidden = lifecycle(
            "hidden-contradiction",
            "visible-target",
            "ctxql:contradicted_by",
            "hidden-reference",
        );
        let hidden_only = AuthorizedSemanticView {
            base: std::sync::Arc::new(LifecycleView {
                identity: identity.clone(),
                pages: vec![vec![hidden.clone()]],
            }),
            control_resources: Default::default(),
            visible_supports: [ClaimId::new("visible-target").unwrap()]
                .into_iter()
                .collect(),
        };
        let hidden_page = hidden_only
            .lifecycle(
                &ClaimId::new("visible-target").unwrap(),
                PageSize::new(1).unwrap(),
                None,
            )
            .unwrap();
        assert!(hidden_page.items().is_empty());
        assert!(hidden_page.next().is_none());

        let visible = lifecycle(
            "visible-supersession",
            "visible-target",
            "ctxql:superseded_by",
            "visible-reference",
        );
        let view = AuthorizedSemanticView {
            base: std::sync::Arc::new(LifecycleView {
                identity: identity.clone(),
                pages: vec![vec![hidden], vec![visible]],
            }),
            control_resources: Default::default(),
            visible_supports: [
                ClaimId::new("visible-target").unwrap(),
                ClaimId::new("visible-supersession").unwrap(),
            ]
            .into_iter()
            .collect(),
        };

        let page = view
            .lifecycle(
                &ClaimId::new("visible-target").unwrap(),
                PageSize::new(1).unwrap(),
                None,
            )
            .unwrap();
        assert_eq!(page.snapshot(), &identity);
        assert_eq!(page.items().len(), 1);
        assert!(page.next().is_none());
        let ExportRecord::Lifecycle { assertion, .. } = &page.items()[0] else {
            panic!("lifecycle record")
        };
        assert_eq!(assertion.id().as_str(), "visible-supersession");
    }

    #[test]
    fn lifecycle_fails_closed_on_non_lifecycle_records() {
        let identity = pin();
        let claim = lifecycle(
            "unexpected",
            "visible-target",
            "ctxql:contradicted_by",
            "reference",
        )
        .claim()
        .unwrap();
        let view = AuthorizedSemanticView {
            base: std::sync::Arc::new(LifecycleView {
                identity,
                pages: vec![vec![ExportRecord::Claim(Box::new(claim))]],
            }),
            control_resources: Default::default(),
            visible_supports: [ClaimId::new("visible-target").unwrap()]
                .into_iter()
                .collect(),
        };
        let error = view
            .lifecycle(
                &ClaimId::new("visible-target").unwrap(),
                PageSize::new(1).unwrap(),
                None,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Invalid);
        assert_eq!(error.message, "non-lifecycle record in lifecycle page");
    }
}
