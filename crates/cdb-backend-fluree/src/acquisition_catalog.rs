//! Immutable capture-bound ontology catalog for provider lookup and host validation.

use crate::authorized_view::ExactTerm;
use crate::semantic::SemanticLedgerOptions;
use crate::semantic_preparation::PreparedAuthorizedView;
use cdb_acquisition::contracts::{EntityResolver, OntologyLookup};
use cdb_acquisition::validator::OntologyAuthority;
use cdb_core::id::{ContentHash, Iri, ResourceId, VersionId};
use cdb_core::ontology_catalog::{OntologyCatalogIdentity, OntologyTerm, OntologyTermKind};
use cdb_core::snapshot::{GraphPin, SnapshotRef};
use cdb_core::{CanonicalValue, Error, Limits, Result};
use std::collections::BTreeMap;

const ACQUISITION_SUPPORT_ONTOLOGY: &[u8] =
    include_bytes!("../../../fixtures/conformance/p6/acquisition-support-ontology.ttl");
const ACQUISITION_SUPPORT_ONTOLOGY_HASH: &str =
    "sha256:7a0adbc53139441fd2906f75cbb3c217036b37687b34aeb1e102aa00fe51b208";
const ACQUISITION: &str = "urn:ctxql:acquisition:v1:";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OntologyDiscoveryText {
    labels: std::collections::BTreeSet<String>,
    definitions: std::collections::BTreeSet<String>,
    synonyms: std::collections::BTreeSet<String>,
}
impl OntologyDiscoveryText {
    pub fn labels(&self) -> &std::collections::BTreeSet<String> {
        &self.labels
    }
    pub fn definitions(&self) -> &std::collections::BTreeSet<String> {
        &self.definitions
    }
    pub fn synonyms(&self) -> &std::collections::BTreeSet<String> {
        &self.synonyms
    }
}

#[derive(Clone)]
pub struct CertifiedOntologyCatalog {
    identity: OntologyCatalogIdentity,
    capture_root: ContentHash,
    terms: BTreeMap<Iri, OntologyTerm>,
    discovery_text: BTreeMap<Iri, OntologyDiscoveryText>,
}
impl CertifiedOntologyCatalog {
    pub fn from_prepared(
        prepared: &PreparedAuthorizedView,
        options: &SemanticLedgerOptions,
    ) -> Result<Self> {
        const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
        const RDFS_SUBCLASS: &str = "http://www.w3.org/2000/01/rdf-schema#subClassOf";
        const RDFS_SUBPROPERTY: &str = "http://www.w3.org/2000/01/rdf-schema#subPropertyOf";
        const RDFS_DOMAIN: &str = "http://www.w3.org/2000/01/rdf-schema#domain";
        const RDFS_RANGE: &str = "http://www.w3.org/2000/01/rdf-schema#range";
        const OWL_DEPRECATED: &str = "http://www.w3.org/2002/07/owl#deprecated";
        const VOCABULARY_STATUS: &str = "urn:ctxql:acquisition:v1:vocabularyStatus";

        let historical = prepared.manifest.ontology_profile.identity
            == cdb_core::recording_v4::ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID;
        let current = prepared.manifest.ontology_profile.identity
            == crate::ontology_profile_v2::ONTOLOGY_PROFILE_V2_ID
            && prepared.manifest.supported_subset.is_none()
            && options.backend.as_str() == cdb_core::recording_v5::BACKEND_ID;
        if !historical && !current {
            if prepared.manifest.ontology_profile.identity
                != crate::ontology_profile_v2::ONTOLOGY_PROFILE_V2_ID
            {
                return Err(Error::invalid("acquisition ontology profile identity"));
            }
            if prepared.manifest.supported_subset.is_some() {
                return Err(Error::invalid(
                    "current acquisition supported-subset marker",
                ));
            }
            return Err(Error::invalid("current acquisition backend identity"));
        }
        let supported = prepared.manifest.supported_subset.as_ref();
        if historical && supported.is_none() {
            return Err(Error::invalid("missing supported-subset manifest"));
        }
        let mut kinds = BTreeMap::<Iri, OntologyTermKind>::new();
        let mut super_terms = BTreeMap::<Iri, std::collections::BTreeSet<Iri>>::new();
        let mut domains = BTreeMap::<Iri, std::collections::BTreeSet<Iri>>::new();
        let mut ranges = BTreeMap::<Iri, std::collections::BTreeSet<Iri>>::new();
        let mut deprecated = std::collections::BTreeSet::new();
        let mut statuses = BTreeMap::<Iri, cdb_core::ontology_catalog::VocabularyStatus>::new();
        let mut discovery_text = BTreeMap::<Iri, OntologyDiscoveryText>::new();
        for quad in &prepared.manifest.schema_quads {
            let Some(subject) = quad.subject.as_iri().and_then(|value| Iri::new(value).ok()) else {
                continue;
            };
            let object_iri = quad.object.as_iri().and_then(|value| Iri::new(value).ok());
            if let ExactTerm::Literal { lexical, .. } = &quad.object {
                record_discovery_text(
                    &mut discovery_text,
                    subject.clone(),
                    &quad.predicate,
                    lexical,
                );
            }
            if quad.predicate == RDF_TYPE {
                let kind = ontology_term_kind(quad.object.as_iri());
                if let Some(kind) = kind {
                    kinds
                        .entry(subject)
                        .and_modify(|current| {
                            if matches!(
                                kind,
                                OntologyTermKind::Property
                                    | OntologyTermKind::RelationType
                                    | OntologyTermKind::ClaimType
                            ) {
                                *current = kind;
                            }
                        })
                        .or_insert(kind);
                }
            } else if let Some(object) = object_iri {
                match quad.predicate.as_str() {
                    RDFS_SUBCLASS | RDFS_SUBPROPERTY => {
                        super_terms.entry(subject).or_default().insert(object);
                    }
                    RDFS_DOMAIN => {
                        domains.entry(subject).or_default().insert(object);
                    }
                    RDFS_RANGE => {
                        ranges.entry(subject).or_default().insert(object);
                    }
                    VOCABULARY_STATUS => {
                        let status = vocabulary_status(object.as_str())?;
                        if statuses.insert(subject, status).is_some() {
                            return Err(Error::invalid("duplicate ontology vocabulary status"));
                        }
                    }
                    _ => {}
                }
            } else if quad.predicate == OWL_DEPRECATED
                && matches!(&quad.object, ExactTerm::Literal { lexical, .. } if lexical == "true" || lexical == "1")
            {
                deprecated.insert(subject);
            }
        }
        extend_acquisition_support(&mut kinds, &mut domains, &mut ranges)?;
        for datatype in ranges
            .values()
            .flatten()
            .filter(|iri| {
                iri.as_str()
                    .starts_with("http://www.w3.org/2001/XMLSchema#")
                    || iri.as_str() == "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString"
            })
            .cloned()
            .collect::<Vec<_>>()
        {
            kinds.entry(datatype).or_insert(OntologyTermKind::Datatype);
        }
        close_hierarchy(&mut super_terms);
        for (term, supers) in super_terms.clone() {
            let inherited_domains = supers
                .iter()
                .flat_map(|parent| domains.get(parent).into_iter().flatten().cloned())
                .collect::<Vec<_>>();
            let inherited_ranges = supers
                .iter()
                .flat_map(|parent| ranges.get(parent).into_iter().flatten().cloned())
                .collect::<Vec<_>>();
            domains
                .entry(term.clone())
                .or_default()
                .extend(inherited_domains);
            ranges.entry(term).or_default().extend(inherited_ranges);
        }
        let terms = kinds
            .into_iter()
            .map(|(iri, kind)| {
                let status = if deprecated.contains(&iri) {
                    cdb_core::ontology_catalog::VocabularyStatus::Deprecated
                } else {
                    statuses
                        .remove(&iri)
                        .unwrap_or(cdb_core::ontology_catalog::VocabularyStatus::Canonical)
                };
                let extraction_eligible = matches!(
                    status,
                    cdb_core::ontology_catalog::VocabularyStatus::Canonical
                        | cdb_core::ontology_catalog::VocabularyStatus::PermittedExtension
                );
                OntologyTerm::new(
                    iri.clone(),
                    kind,
                    status,
                    extraction_eligible,
                    super_terms.remove(&iri).unwrap_or_default(),
                    domains.remove(&iri).unwrap_or_default(),
                    ranges.remove(&iri).unwrap_or_default(),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let catalog_root = ContentHash::of_bytes(
            &CanonicalValue::Array(terms.iter().map(OntologyTerm::projection).collect())
                .canonical_bytes(Limits::default())?,
        );
        let capture = SnapshotRef::new(
            options.backend.clone(),
            GraphPin::new(
                options.authority.clone(),
                options.ledger.clone(),
                VersionId::new(prepared.manifest.capture.t.to_string())?,
                ResourceId::new(&prepared.manifest.capture.commit_cid)?,
            ),
        );
        let (profile_identity, profile_root, coverage_root, caveat_root) =
            if let Some(supported) = supported {
                let input = supported.input();
                (
                    prepared.manifest.ontology_profile.identity.clone(),
                    supported.root(Limits::default())?,
                    input.final_gate3_semantic_coverage_root.clone(),
                    input.caveat_set_root.clone(),
                )
            } else {
                // The current acquisition profile is explicitly raw and
                // uncertified. Bind it to this exact prepared schema image;
                // never reuse the archived v3 certification roots.
                let profile_root = ContentHash::of_bytes(
                    &CanonicalValue::object([
                        (
                            "identity".into(),
                            CanonicalValue::string(
                                cdb_core::recording_v5::CURRENT_ACQUISITION_PROFILE_ID,
                            ),
                        ),
                        (
                            "schema_root".into(),
                            CanonicalValue::string(prepared.manifest.schema_root.as_str()),
                        ),
                        (
                            "backend".into(),
                            CanonicalValue::string(cdb_core::recording_v5::BACKEND_ID),
                        ),
                        (
                            "purpose".into(),
                            CanonicalValue::string("acquisition-catalog-only"),
                        ),
                    ])?
                    .canonical_bytes(Limits::default())?,
                );
                (
                    cdb_core::recording_v5::CURRENT_ACQUISITION_PROFILE_ID.to_owned(),
                    profile_root.clone(),
                    ContentHash::of_bytes(
                        format!(
                            "ctxql-current-acquisition-coverage/v1\0{}",
                            profile_root.as_str()
                        )
                        .as_bytes(),
                    ),
                    ContentHash::of_bytes(b"ctxql-current-acquisition-caveat/uncertified-v1"),
                )
            };
        let identity = OntologyCatalogIdentity::new(
            capture,
            profile_identity,
            profile_root,
            catalog_root,
            coverage_root,
            caveat_root,
        )?;
        let mut catalog = Self::new(identity, terms)?;
        discovery_text.retain(|iri, _| catalog.terms.contains_key(iri));
        catalog.discovery_text = discovery_text;
        Ok(catalog)
    }

    pub fn new(identity: OntologyCatalogIdentity, terms: Vec<OntologyTerm>) -> Result<Self> {
        identity.verify_terms(&terms, Limits::default())?;
        let mut indexed = BTreeMap::new();
        for term in terms {
            if indexed.insert(term.iri().clone(), term).is_some() {
                return Err(Error::invalid("duplicate ontology catalog term"));
            }
        }
        let capture_root = ContentHash::of_bytes(
            &identity
                .capture()
                .projection()
                .canonical_bytes(Limits::default())?,
        );
        Ok(Self {
            identity,
            capture_root,
            terms: indexed,
            discovery_text: BTreeMap::new(),
        })
    }
    pub fn identity(&self) -> &OntologyCatalogIdentity {
        &self.identity
    }
    pub fn capture_token(&self) -> &str {
        self.capture_root.as_str()
    }
    pub fn terms(&self) -> impl Iterator<Item = &OntologyTerm> {
        self.terms.values()
    }
    pub fn discovery_text(&self, iri: &Iri) -> Option<&OntologyDiscoveryText> {
        self.discovery_text.get(iri)
    }
}

fn record_discovery_text(
    values: &mut BTreeMap<Iri, OntologyDiscoveryText>,
    subject: Iri,
    predicate: &str,
    lexical: &str,
) {
    if lexical.is_empty() {
        return;
    }
    match predicate {
        "http://www.w3.org/2000/01/rdf-schema#label"
        | "http://www.w3.org/2004/02/skos/core#prefLabel" => {
            values
                .entry(subject)
                .or_default()
                .labels
                .insert(lexical.to_owned());
        }
        "http://www.w3.org/2000/01/rdf-schema#comment"
        | "http://www.w3.org/2004/02/skos/core#definition" => {
            values
                .entry(subject)
                .or_default()
                .definitions
                .insert(lexical.to_owned());
        }
        "http://www.w3.org/2004/02/skos/core#altLabel"
        | "http://www.w3.org/2004/02/skos/core#hiddenLabel" => {
            values
                .entry(subject)
                .or_default()
                .synonyms
                .insert(lexical.to_owned());
        }
        _ => {}
    }
}

fn extend_acquisition_support(
    kinds: &mut BTreeMap<Iri, OntologyTermKind>,
    domains: &mut BTreeMap<Iri, std::collections::BTreeSet<Iri>>,
    ranges: &mut BTreeMap<Iri, std::collections::BTreeSet<Iri>>,
) -> Result<()> {
    if ContentHash::of_bytes(ACQUISITION_SUPPORT_ONTOLOGY).as_str()
        != ACQUISITION_SUPPORT_ONTOLOGY_HASH
    {
        return Err(Error::new(
            cdb_core::ErrorKind::Conflict,
            "acquisition support ontology differs",
        ));
    }
    let iri = |suffix: &str| Iri::new(format!("{ACQUISITION}{suffix}"));
    for suffix in [
        "Claim",
        "ClaimType",
        "RelationType",
        "VocabularyStatus",
        "ConfiguredGraph",
        "AcquisitionConfiguration",
    ] {
        kinds.insert(iri(suffix)?, OntologyTermKind::Class);
    }
    for (suffix, domain, range) in [
        ("claimType", Some("Claim"), "ClaimType"),
        ("relationType", Some("Claim"), "RelationType"),
        ("vocabularyStatus", None, "VocabularyStatus"),
    ] {
        let property = iri(suffix)?;
        kinds.insert(property.clone(), OntologyTermKind::Property);
        if let Some(domain) = domain {
            domains
                .entry(property.clone())
                .or_default()
                .insert(iri(domain)?);
        }
        ranges.entry(property).or_default().insert(iri(range)?);
    }
    for suffix in ["TypeAssertionClaimType", "BusinessRelationshipClaimType"] {
        kinds.insert(iri(suffix)?, OntologyTermKind::ClaimType);
    }
    for suffix in [
        "TypeAssertionRelationType",
        "BusinessRelationshipRelationType",
    ] {
        kinds.insert(iri(suffix)?, OntologyTermKind::RelationType);
    }
    Ok(())
}

fn vocabulary_status(iri: &str) -> Result<cdb_core::ontology_catalog::VocabularyStatus> {
    use cdb_core::ontology_catalog::VocabularyStatus;
    match iri {
        "urn:ctxql:acquisition:v1:Canonical" => Ok(VocabularyStatus::Canonical),
        "urn:ctxql:acquisition:v1:PermittedExtension" => Ok(VocabularyStatus::PermittedExtension),
        "urn:ctxql:acquisition:v1:Discouraged" => Ok(VocabularyStatus::Discouraged),
        "urn:ctxql:acquisition:v1:Deprecated" => Ok(VocabularyStatus::Deprecated),
        "urn:ctxql:acquisition:v1:NotEligible" => Ok(VocabularyStatus::NotEligible),
        _ => Err(Error::invalid("unknown ontology vocabulary status")),
    }
}

fn ontology_term_kind(type_iri: Option<&str>) -> Option<OntologyTermKind> {
    match type_iri {
        Some("urn:ctxql:acquisition:v1:ClaimType") => Some(OntologyTermKind::ClaimType),
        Some("urn:ctxql:acquisition:v1:RelationType") => Some(OntologyTermKind::RelationType),
        Some("http://www.w3.org/2000/01/rdf-schema#Class")
        | Some("http://www.w3.org/2002/07/owl#Class") => Some(OntologyTermKind::Class),
        Some("http://www.w3.org/1999/02/22-rdf-syntax-ns#Property")
        | Some("http://www.w3.org/2002/07/owl#ObjectProperty")
        | Some("http://www.w3.org/2002/07/owl#DatatypeProperty")
        | Some("http://www.w3.org/2002/07/owl#AnnotationProperty") => {
            Some(OntologyTermKind::Property)
        }
        Some("http://www.w3.org/2000/01/rdf-schema#Datatype")
        | Some("http://www.w3.org/2002/07/owl#Datatype") => Some(OntologyTermKind::Datatype),
        _ => None,
    }
}

fn close_hierarchy(values: &mut BTreeMap<Iri, std::collections::BTreeSet<Iri>>) {
    loop {
        let before = values.clone();
        for parents in values.values_mut() {
            let inherited = parents
                .iter()
                .flat_map(|parent| before.get(parent).into_iter().flatten().cloned())
                .collect::<Vec<_>>();
            parents.extend(inherited);
        }
        if *values == before {
            break;
        }
    }
}

impl OntologyAuthority for CertifiedOntologyCatalog {
    fn extraction_term(&self, iri: &Iri) -> Result<OntologyTerm> {
        self.terms
            .get(iri)
            .filter(|term| term.extraction_eligible())
            .cloned()
            .ok_or_else(|| Error::invalid("ontology term outside certified extraction catalog"))
    }
}
impl OntologyLookup for CertifiedOntologyCatalog {
    fn describe(&self, capture: &str, iri: &Iri) -> Result<Option<CanonicalValue>> {
        if capture != self.capture_token() {
            return Err(Error::invalid("ontology catalog capture mismatch"));
        }
        Ok(self.terms.get(iri).map(OntologyTerm::projection))
    }
}

/// Exact-capture entity index. Existing identity wins; otherwise a stable IRI
/// is minted from exact spelling and type without normalization or fuzzy match.
#[derive(Clone)]
pub struct CaptureEntityResolver {
    capture: String,
    existing: BTreeMap<(String, Iri), Iri>,
}
impl CaptureEntityResolver {
    pub fn new(
        capture: impl Into<String>,
        existing: impl IntoIterator<Item = (String, Iri, Iri)>,
    ) -> Result<Self> {
        let capture = capture.into();
        ContentHash::parse(&capture)?;
        let mut index = BTreeMap::new();
        for (spelling, kind, entity) in existing {
            if spelling.is_empty() || spelling.chars().any(char::is_control) {
                return Err(Error::invalid("entity source spelling"));
            }
            if index.insert((spelling, kind), entity).is_some() {
                return Err(Error::invalid("ambiguous existing entity identity"));
            }
        }
        Ok(Self {
            capture,
            existing: index,
        })
    }
}
impl EntityResolver for CaptureEntityResolver {
    fn resolve(
        &self,
        capture: &str,
        text_version: &ContentHash,
        extraction_run: &str,
        local_key: &str,
        source_spelling: &str,
        proposed_type: &Iri,
    ) -> Result<Iri> {
        if capture != self.capture
            || extraction_run.is_empty()
            || local_key.is_empty()
            || source_spelling.is_empty()
            || source_spelling.chars().any(char::is_control)
        {
            return Err(Error::invalid("entity resolution scope"));
        }
        if let Some(existing) = self
            .existing
            .get(&(source_spelling.to_owned(), proposed_type.clone()))
        {
            return Ok(existing.clone());
        }
        let value = CanonicalValue::object([
            (
                "schema".into(),
                CanonicalValue::string("ctxql-entity-identity/v1"),
            ),
            ("capture".into(), CanonicalValue::string(capture)),
            (
                "text_version".into(),
                CanonicalValue::string(text_version.as_str()),
            ),
            (
                "extraction_run".into(),
                CanonicalValue::string(extraction_run),
            ),
            ("local_key".into(), CanonicalValue::string(local_key)),
            (
                "proposed_type".into(),
                CanonicalValue::string(proposed_type.as_str()),
            ),
        ])?;
        let root = ContentHash::of_bytes(&value.canonical_bytes(Limits::default())?);
        Iri::new(format!("urn:ctxql:entity:{}", &root.as_str()[7..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_ontology_individuals_have_authoritative_relation_and_claim_kinds() {
        assert_eq!(
            ontology_term_kind(Some("urn:ctxql:acquisition:v1:RelationType")),
            Some(OntologyTermKind::RelationType)
        );
        assert_eq!(
            ontology_term_kind(Some("urn:ctxql:acquisition:v1:ClaimType")),
            Some(OntologyTermKind::ClaimType)
        );
        assert_eq!(
            ontology_term_kind(Some("http://www.w3.org/2002/07/owl#Class")),
            Some(OntologyTermKind::Class)
        );
    }

    #[test]
    fn catalog_does_not_promote_arbitrary_classes_to_relation_or_claim_types() {
        use cdb_core::ontology_catalog::VocabularyStatus;
        use cdb_core::snapshot::GraphPin;
        let class = OntologyTerm::new(
            Iri::new("urn:type:ordinary-class").unwrap(),
            OntologyTermKind::Class,
            VocabularyStatus::Canonical,
            true,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap();
        let root = ContentHash::of_bytes(
            &CanonicalValue::Array(vec![class.projection()])
                .canonical_bytes(Limits::default())
                .unwrap(),
        );
        let identity = OntologyCatalogIdentity::new(
            SnapshotRef::new(
                cdb_core::id::BackendId::new("backend").unwrap(),
                GraphPin::new(
                    cdb_core::id::AuthorityId::new("authority").unwrap(),
                    cdb_core::id::GraphId::new("graph").unwrap(),
                    VersionId::new("1").unwrap(),
                    ResourceId::new("cid").unwrap(),
                ),
            ),
            cdb_core::recording_v4::ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID,
            ContentHash::of_bytes(b"profile"),
            root,
            ContentHash::of_bytes(b"coverage"),
            ContentHash::of_bytes(b"caveats"),
        )
        .unwrap();
        let catalog = CertifiedOntologyCatalog::new(identity, vec![class]).unwrap();
        assert!(catalog
            .require_extraction_term(
                &Iri::new("urn:type:ordinary-class").unwrap(),
                OntologyTermKind::RelationType,
            )
            .is_err());
    }

    #[test]
    fn discovery_text_accepts_only_traceable_ontology_annotations() {
        let iri = Iri::new("urn:test:Borrower").unwrap();
        let mut values = BTreeMap::new();
        record_discovery_text(
            &mut values,
            iri.clone(),
            "http://www.w3.org/2000/01/rdf-schema#label",
            "Borrower",
        );
        record_discovery_text(
            &mut values,
            iri.clone(),
            "http://www.w3.org/2004/02/skos/core#definition",
            "A party that owes an obligation.",
        );
        record_discovery_text(
            &mut values,
            iri.clone(),
            "http://www.w3.org/2004/02/skos/core#altLabel",
            "Obligor",
        );
        record_discovery_text(
            &mut values,
            Iri::new("urn:test:Uncertified").unwrap(),
            "urn:unapproved:displayName",
            "Not certified search text",
        );

        assert!(!values.contains_key(&Iri::new("urn:test:Uncertified").unwrap()));
        let text = values.get(&iri).unwrap();
        assert_eq!(
            text.labels().iter().cloned().collect::<Vec<_>>(),
            ["Borrower"]
        );
        assert_eq!(
            text.definitions().iter().cloned().collect::<Vec<_>>(),
            ["A party that owes an obligation."]
        );
        assert_eq!(
            text.synonyms().iter().cloned().collect::<Vec<_>>(),
            ["Obligor"]
        );
    }

    #[test]
    fn minted_entities_are_document_run_and_local_key_scoped() {
        let capture = ContentHash::of_bytes(b"capture");
        let resolver =
            CaptureEntityResolver::new(capture.as_str(), std::iter::empty::<(String, Iri, Iri)>())
                .unwrap();
        let kind = Iri::new("urn:type:organization").unwrap();
        let version_a = ContentHash::of_bytes(b"document-a");
        let version_b = ContentHash::of_bytes(b"document-b");
        let resolve = |version: &ContentHash, run: &str, local: &str| {
            resolver
                .resolve(capture.as_str(), version, run, local, "Acme", &kind)
                .unwrap()
        };
        let identity = resolve(&version_a, "run-a", "entity-a");
        assert_eq!(identity, resolve(&version_a, "run-a", "entity-a"));
        assert_ne!(identity, resolve(&version_b, "run-a", "entity-a"));
        assert_ne!(identity, resolve(&version_a, "run-b", "entity-a"));
        assert_ne!(identity, resolve(&version_a, "run-a", "entity-b"));
    }
}
