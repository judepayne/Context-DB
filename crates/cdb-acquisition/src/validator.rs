use crate::candidates::{AdvisoryBundle, CandidateObject, LocalId};
use crate::contracts::EntityResolver;
use crate::coordinates::CoordinateMap;
use crate::lineage::strict_lineage;
use cdb_core::claim::CandidateClaim;
use cdb_core::id::{BundleId, ContentHash, ExtractionRunId, Iri, SourceId};
use cdb_core::ontology_catalog::OntologyTermKind;
use cdb_core::semantic_admission::{
    bundle_descriptor_root, deterministic_claim_id, ValidatedSemanticBundle,
};
use cdb_core::snapshot::SnapshotRef;
use cdb_core::{CanonicalValue as V, Error, ExactNumber, Limits, Result, Timestamp};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDFS_CLASS: &str = "http://www.w3.org/2000/01/rdf-schema#Class";
const RDF_LANG_STRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";
const XSD_BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";
const XSD_INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
const XSD_DECIMAL: &str = "http://www.w3.org/2001/XMLSchema#decimal";
const XSD_DATETIME: &str = "http://www.w3.org/2001/XMLSchema#dateTime";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const BUSINESS_RELATION_TYPE: &str = "urn:ctxql:acquisition:v1:BusinessRelationshipRelationType";
const BUSINESS_CLAIM_TYPE: &str = "urn:ctxql:acquisition:v1:BusinessRelationshipClaimType";
const TYPE_ASSERTION_RELATION_TYPE: &str = "urn:ctxql:acquisition:v1:TypeAssertionRelationType";
const TYPE_ASSERTION_CLAIM_TYPE: &str = "urn:ctxql:acquisition:v1:TypeAssertionClaimType";
const PROVISIONAL_ENTITY_CLASS: &str = "urn:ctxql:poc:soft:Entity";
const PROVISIONAL_ENTITY_PREFIX: &str = "urn:ctxql:poc:soft:entity:";
const PROVISIONAL_PREDICATE_PREFIX: &str = "urn:ctxql:poc:soft:predicate:";

pub trait OntologyAuthority {
    fn extraction_term(&self, iri: &Iri) -> Result<cdb_core::ontology_catalog::OntologyTerm>;

    fn require_extraction_term(&self, iri: &Iri, kind: OntologyTermKind) -> Result<()> {
        let term = self.extraction_term(iri)?;
        if term.kind() != kind || !term.extraction_eligible() {
            return Err(Error::invalid("ontology term not extraction eligible"));
        }
        Ok(())
    }
}

pub struct ValidationInput<'a> {
    pub extraction_run: ExtractionRunId,
    pub validation_capture: SnapshotRef,
    pub descriptor: V,
    pub source_id: SourceId,
    pub document: &'a str,
    pub attempt_id: &'a str,
    pub window_id: &'a str,
    pub coordinates: &'a CoordinateMap,
    pub max_spans_per_claim: usize,
    pub limits: Limits,
}

pub fn validate_bundle<O: OntologyAuthority, E: EntityResolver>(
    advisory: AdvisoryBundle,
    input: ValidationInput<'_>,
    ontology: &O,
    entities: &E,
) -> Result<ValidatedSemanticBundle> {
    advisory.validate_shape(&Default::default())?;
    ensure_connected(&advisory)?;
    let bundle_identity = V::object([
        (
            "local_bundle_id".into(),
            V::string(advisory.local_bundle_id.as_str()),
        ),
        (
            "extraction_run".into(),
            V::string(input.extraction_run.as_str()),
        ),
        ("source_id".into(), V::string(input.source_id.as_str())),
        ("window_id".into(), V::string(input.window_id)),
        (
            "candidate_descriptor_root".into(),
            V::string(
                ContentHash::of_bytes(&input.descriptor.canonical_bytes(input.limits)?).as_str(),
            ),
        ),
        (
            "validation_capture_root".into(),
            V::string(
                ContentHash::of_bytes(
                    &input
                        .validation_capture
                        .projection()
                        .canonical_bytes(input.limits)?,
                )
                .as_str(),
            ),
        ),
    ])?;
    let bundle_id = BundleId::new(format!(
        "bundle:{}",
        &ContentHash::of_bytes(&bundle_identity.canonical_bytes(input.limits)?).as_str()[7..]
    ))?;
    let descriptor_root = bundle_descriptor_root(
        &bundle_id,
        &input.extraction_run,
        &input.validation_capture,
        &input.descriptor,
        input.limits,
    )?;

    let capture = input
        .validation_capture
        .projection()
        .canonical_bytes(input.limits)?;
    let capture = ContentHash::of_bytes(&capture).as_str().to_owned();
    let type_objects = validate_type_assertion_shapes(&advisory, ontology)?;
    let mut resolved = BTreeMap::new();
    for entity in &advisory.entities {
        let iri = if let Some(asserted_type) = type_objects.get(entity.local_id()) {
            asserted_type.clone()
        } else {
            ontology.require_extraction_term(entity.proposed_type(), OntologyTermKind::Class)?;
            entities.resolve(
                &capture,
                input.coordinates.text_version(),
                input.extraction_run.as_str(),
                entity.local_id().as_str(),
                entity.source_spelling(),
                entity.proposed_type(),
            )?
        };
        if let Some(previous) = resolved.insert(entity.local_id().clone(), iri.clone()) {
            if previous != iri {
                return Err(Error::invalid("unstable entity resolution"));
            }
        }
    }
    let metadata = advisory
        .metadata
        .iter()
        .map(|value| (&value.local_claim_id, value))
        .collect::<BTreeMap<_, _>>();
    let mut claims = Vec::with_capacity(advisory.claims.len());
    for claim in &advisory.claims {
        let type_assertion = claim.predicate.as_str() == RDF_TYPE;
        let property = if type_assertion {
            require_exact_claim_metadata(
                claim,
                TYPE_ASSERTION_RELATION_TYPE,
                TYPE_ASSERTION_CLAIM_TYPE,
                ontology,
            )?;
            if !claim.endpoint_type_claims.is_empty() || claim.valid_time.is_some() {
                return Err(Error::invalid("invalid endpoint type assertion metadata"));
            }
            None
        } else {
            require_exact_claim_metadata(
                claim,
                BUSINESS_RELATION_TYPE,
                BUSINESS_CLAIM_TYPE,
                ontology,
            )?;
            let property = ontology.extraction_term(&claim.predicate)?;
            if property.kind() != OntologyTermKind::Property || !property.extraction_eligible() {
                return Err(Error::invalid("ontology property not extraction eligible"));
            }
            Some(property)
        };
        let subject = resolved
            .get(&claim.subject)
            .ok_or_else(|| Error::invalid("unresolved validated subject"))?;
        let (object, object_type) = match &claim.object {
            CandidateObject::Entity(local) => {
                if !type_assertion && type_objects.contains_key(local) {
                    return Err(Error::invalid(
                        "ontology type token used as business entity",
                    ));
                }
                let entity = advisory
                    .entities
                    .iter()
                    .find(|entity| entity.local_id() == local)
                    .ok_or_else(|| Error::invalid("unresolved validated object"))?;
                (
                    V::string(
                        resolved
                            .get(local)
                            .ok_or_else(|| Error::invalid("unresolved validated object"))?
                            .as_str(),
                    ),
                    entity.proposed_type().clone(),
                )
            }
            CandidateObject::Literal(literal) => {
                ontology.require_extraction_term(literal.datatype(), OntologyTermKind::Datatype)?;
                if literal.language().is_some() != (literal.datatype().as_str() == RDF_LANG_STRING)
                {
                    return Err(Error::invalid("literal language/datatype mismatch"));
                }
                (literal_value(literal)?, literal.datatype().clone())
            }
        };
        let subject_type = advisory
            .entities
            .iter()
            .find(|entity| entity.local_id() == &claim.subject)
            .ok_or_else(|| Error::invalid("unresolved subject type"))?
            .proposed_type()
            .clone();
        if let Some(property) = &property {
            validate_property_compatibility(
                ontology,
                property,
                &subject_type,
                &object_type,
                matches!(claim.object, CandidateObject::Literal(_)),
            )?;
            validate_endpoint_type_references(claim, &advisory, &subject_type, &object_type)?;
        }
        let metadata = metadata
            .get(&claim.local_claim_id)
            .ok_or_else(|| Error::invalid("missing claim metadata"))?;
        validate_temporal_support(claim, metadata, &advisory)?;
        let spans = input.coordinates.resolve(
            input.document,
            input.attempt_id,
            input.window_id,
            &metadata.locator,
            &metadata.text_version,
            &metadata.coordinates,
            input.max_spans_per_claim,
        )?;
        let lineage = strict_lineage(
            &input.source_id,
            &metadata.locator,
            &metadata.text_version,
            input.coordinates.text_object(),
            &spans,
            input.max_spans_per_claim,
        )?;
        let provisional_id = format!(
            "urn:ctxql:provisional:{}",
            &ContentHash::of_bytes(claim.local_claim_id.as_str().as_bytes()).as_str()[7..]
        );
        let mut value = V::object([
            ("claim_id".into(), V::string(provisional_id)),
            ("subject_id".into(), V::string(subject.as_str())),
            ("relation".into(), V::string(claim.predicate.as_str())),
            ("object_id".into(), object),
            (
                "relation_type".into(),
                V::string(claim.relation_type.as_str()),
            ),
            ("subject_type".into(), V::string(subject_type.as_str())),
            ("object_type".into(), V::string(object_type.as_str())),
            ("claim_type".into(), V::string(claim.claim_type.as_str())),
            (
                "confidence".into(),
                V::Number(ExactNumber::parse(
                    claim.confidence.as_deref().unwrap_or("1"),
                )?),
            ),
            (
                "grounding_level".into(),
                V::string("source_spans_available"),
            ),
            ("lineage".into(), lineage.projection()),
            (
                "ext".into(),
                V::object([(
                    "ctxql.acquisition/v1".into(),
                    V::object([
                        (
                            "descriptor_root".into(),
                            V::string(descriptor_root.as_str()),
                        ),
                        (
                            "provider_local_claim_id".into(),
                            V::string(claim.local_claim_id.as_str()),
                        ),
                    ])?,
                )])?,
            ),
        ])?;
        if let Some(valid_time) = &claim.valid_time {
            let V::Object(fields) = &mut value else {
                unreachable!()
            };
            fields.insert("valid_time".into(), V::string(valid_time));
        }
        let provisional = CandidateClaim::from_value(&value)?;
        let final_id = deterministic_claim_id(
            &descriptor_root,
            claim.local_claim_id.as_str(),
            &provisional,
            input.limits,
        )?;
        let V::Object(fields) = &mut value else {
            unreachable!()
        };
        fields.insert("claim_id".into(), V::string(final_id.as_str()));
        claims.push((
            claim.local_claim_id.as_str().to_owned(),
            CandidateClaim::from_value(&value)?,
        ));
    }
    ValidatedSemanticBundle::new(
        bundle_id,
        input.extraction_run,
        input.validation_capture,
        input.descriptor,
        claims,
        input.limits,
    )
}

/// Validate the host-constructed, deliberately narrow soft-mapping wire.
///
/// This path admits only a single source-grounded string claim using host-owned
/// provisional IRIs. It intentionally does not weaken `validate_bundle` or
/// treat provider-supplied ontology terms as authoritative.
pub fn validate_provisional_bundle(
    advisory: AdvisoryBundle,
    input: ValidationInput<'_>,
) -> Result<ValidatedSemanticBundle> {
    advisory.validate_shape(&Default::default())?;
    ensure_connected(&advisory)?;
    if advisory.entities.len() != 1 || advisory.claims.len() != 1 || advisory.metadata.len() != 1 {
        return Err(Error::invalid(
            "provisional bundle must contain exactly one claim",
        ));
    }

    let entity = &advisory.entities[0];
    let claim = &advisory.claims[0];
    let metadata = &advisory.metadata[0];
    if claim.subject != *entity.local_id() || metadata.local_claim_id != claim.local_claim_id {
        return Err(Error::invalid("invalid provisional claim binding"));
    }
    if entity.proposed_type().as_str() != PROVISIONAL_ENTITY_CLASS
        || !host_hash_iri(entity.source_spelling(), PROVISIONAL_ENTITY_PREFIX)
        || !host_hash_iri(claim.predicate.as_str(), PROVISIONAL_PREDICATE_PREFIX)
    {
        return Err(Error::invalid(
            "provisional IRI outside host-owned namespace",
        ));
    }
    let subject = Iri::new(entity.source_spelling())?;
    if claim.relation_type.as_str() != BUSINESS_RELATION_TYPE
        || claim.claim_type.as_str() != BUSINESS_CLAIM_TYPE
    {
        return Err(Error::invalid("invalid provisional business claim types"));
    }
    if !claim.endpoint_type_claims.is_empty() {
        return Err(Error::invalid(
            "provisional claims cannot reference endpoint type assertions",
        ));
    }
    let CandidateObject::Literal(literal) = &claim.object else {
        return Err(Error::invalid(
            "provisional object must be a string literal",
        ));
    };
    if literal.datatype().as_str() != XSD_STRING || literal.language().is_some() {
        return Err(Error::invalid("provisional object must be xsd:string"));
    }
    // A one-claim provisional bundle cannot contain an independent temporal
    // qualifier. Keep this call so the ordinary temporal support rules remain
    // authoritative if the shape evolves.
    validate_temporal_support(claim, metadata, &advisory)?;

    let bundle_identity = V::object([
        (
            "local_bundle_id".into(),
            V::string(advisory.local_bundle_id.as_str()),
        ),
        (
            "extraction_run".into(),
            V::string(input.extraction_run.as_str()),
        ),
        ("source_id".into(), V::string(input.source_id.as_str())),
        ("window_id".into(), V::string(input.window_id)),
        (
            "candidate_descriptor_root".into(),
            V::string(
                ContentHash::of_bytes(&input.descriptor.canonical_bytes(input.limits)?).as_str(),
            ),
        ),
        (
            "validation_capture_root".into(),
            V::string(
                ContentHash::of_bytes(
                    &input
                        .validation_capture
                        .projection()
                        .canonical_bytes(input.limits)?,
                )
                .as_str(),
            ),
        ),
    ])?;
    let bundle_id = BundleId::new(format!(
        "bundle:{}",
        &ContentHash::of_bytes(&bundle_identity.canonical_bytes(input.limits)?).as_str()[7..]
    ))?;
    let descriptor_root = bundle_descriptor_root(
        &bundle_id,
        &input.extraction_run,
        &input.validation_capture,
        &input.descriptor,
        input.limits,
    )?;

    let spans = input.coordinates.resolve(
        input.document,
        input.attempt_id,
        input.window_id,
        &metadata.locator,
        &metadata.text_version,
        &metadata.coordinates,
        input.max_spans_per_claim,
    )?;
    let lineage = strict_lineage(
        &input.source_id,
        &metadata.locator,
        &metadata.text_version,
        input.coordinates.text_object(),
        &spans,
        input.max_spans_per_claim,
    )?;
    let provisional_id = format!(
        "urn:ctxql:provisional:{}",
        &ContentHash::of_bytes(claim.local_claim_id.as_str().as_bytes()).as_str()[7..]
    );
    let mut provenance = vec![
        (
            "descriptor_root".into(),
            V::string(descriptor_root.as_str()),
        ),
        (
            "provider_local_claim_id".into(),
            V::string(claim.local_claim_id.as_str()),
        ),
        ("mapping_status".into(), V::string("provisional")),
    ];
    {
        let raw = input.descriptor.field("raw_fact")?;
        let subject_label = raw.field("subject")?.as_str()?;
        let predicate_label = raw.field("predicate")?.as_str()?;
        let object_label = raw.field("object")?.as_str()?;
        let line_id = raw.field("line_id")?.as_str()?;
        if metadata.coordinates.len() != 1 || metadata.coordinates[0].line_id.as_str() != line_id {
            return Err(Error::invalid(
                "provisional fact line does not match evidence",
            ));
        }
        // A label alone cannot identify an entity across independent sources.
        // The host-issued source ID and grounded locator bind the fallback IRI.
        let entity_seed = format!(
            "{}\0{}\0{subject_label}",
            input.source_id.as_str(),
            metadata.locator.as_str()
        );
        let expected_entity = format!(
            "{PROVISIONAL_ENTITY_PREFIX}{}",
            &ContentHash::of_bytes(entity_seed.to_lowercase().as_bytes()).as_str()[7..]
        );
        let expected_predicate = format!(
            "{PROVISIONAL_PREDICATE_PREFIX}{}",
            &ContentHash::of_bytes(predicate_label.to_lowercase().as_bytes()).as_str()[7..]
        );
        if subject.as_str() != expected_entity
            || claim.predicate.as_str() != expected_predicate
            || literal.lexical() != object_label
        {
            return Err(Error::invalid("provisional labels do not match claim"));
        }
        provenance.extend([
            ("subject_label".into(), V::string(subject_label)),
            ("predicate_label".into(), V::string(predicate_label)),
        ]);
    }
    let mut value = V::object([
        ("claim_id".into(), V::string(provisional_id)),
        ("subject_id".into(), V::string(subject.as_str())),
        ("relation".into(), V::string(claim.predicate.as_str())),
        ("object_id".into(), literal_value(literal)?),
        (
            "relation_type".into(),
            V::string(claim.relation_type.as_str()),
        ),
        ("subject_type".into(), V::string(PROVISIONAL_ENTITY_CLASS)),
        ("object_type".into(), V::string(XSD_STRING)),
        ("claim_type".into(), V::string(claim.claim_type.as_str())),
        (
            "confidence".into(),
            V::Number(ExactNumber::parse(
                claim.confidence.as_deref().unwrap_or("1"),
            )?),
        ),
        (
            "grounding_level".into(),
            V::string("source_spans_available"),
        ),
        ("lineage".into(), lineage.projection()),
        (
            "ext".into(),
            V::object([("ctxql.acquisition/v1".into(), V::object(provenance)?)])?,
        ),
    ])?;
    let provisional = CandidateClaim::from_value(&value)?;
    let final_id = deterministic_claim_id(
        &descriptor_root,
        claim.local_claim_id.as_str(),
        &provisional,
        input.limits,
    )?;
    let V::Object(fields) = &mut value else {
        unreachable!()
    };
    fields.insert("claim_id".into(), V::string(final_id.as_str()));
    let validated = CandidateClaim::from_value(&value)?;

    ValidatedSemanticBundle::new(
        bundle_id,
        input.extraction_run,
        input.validation_capture,
        input.descriptor,
        vec![(claim.local_claim_id.as_str().to_owned(), validated)],
        input.limits,
    )
}

fn host_hash_iri(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn validate_property_compatibility<O: OntologyAuthority>(
    ontology: &O,
    property: &cdb_core::ontology_catalog::OntologyTerm,
    subject_type: &Iri,
    object_type: &Iri,
    literal_object: bool,
) -> Result<()> {
    for domain in property.domains() {
        if !type_compatible(ontology, subject_type, domain, OntologyTermKind::Class)? {
            return Err(Error::invalid("ontology property domain mismatch"));
        }
    }
    let expected_kind = if literal_object {
        OntologyTermKind::Datatype
    } else {
        OntologyTermKind::Class
    };
    for range in property.ranges() {
        if !type_compatible(ontology, object_type, range, expected_kind)? {
            return Err(Error::invalid("ontology property range mismatch"));
        }
    }
    Ok(())
}

fn type_compatible<O: OntologyAuthority>(
    ontology: &O,
    actual: &Iri,
    expected: &Iri,
    kind: OntologyTermKind,
) -> Result<bool> {
    let term = ontology.extraction_term(actual)?;
    if term.kind() != kind || !term.extraction_eligible() {
        return Err(Error::invalid("endpoint type not extraction eligible"));
    }
    Ok(actual == expected || term.super_terms().contains(expected))
}

fn require_exact_claim_metadata<O: OntologyAuthority>(
    claim: &crate::candidates::AdvisoryClaim,
    relation_type: &str,
    claim_type: &str,
    ontology: &O,
) -> Result<()> {
    if claim.relation_type.as_str() != relation_type || claim.claim_type.as_str() != claim_type {
        return Err(Error::invalid("relation and claim type are incompatible"));
    }
    ontology.require_extraction_term(&claim.relation_type, OntologyTermKind::RelationType)?;
    ontology.require_extraction_term(&claim.claim_type, OntologyTermKind::ClaimType)
}

fn validate_type_assertion_shapes<O: OntologyAuthority>(
    bundle: &AdvisoryBundle,
    ontology: &O,
) -> Result<BTreeMap<LocalId, Iri>> {
    let mut type_objects = BTreeMap::new();
    for claim in &bundle.claims {
        if claim.predicate.as_str() != RDF_TYPE {
            continue;
        }
        require_exact_claim_metadata(
            claim,
            TYPE_ASSERTION_RELATION_TYPE,
            TYPE_ASSERTION_CLAIM_TYPE,
            ontology,
        )?;
        let CandidateObject::Entity(type_object) = &claim.object else {
            return Err(Error::invalid(
                "type assertion object must be an ontology class",
            ));
        };
        if type_object == &claim.subject {
            return Err(Error::invalid("self-referential endpoint type assertion"));
        }
        let subject = bundle
            .entities
            .iter()
            .find(|entity| entity.local_id() == &claim.subject)
            .ok_or_else(|| Error::invalid("type assertion subject"))?;
        let object = bundle
            .entities
            .iter()
            .find(|entity| entity.local_id() == type_object)
            .ok_or_else(|| Error::invalid("type assertion object"))?;
        if object.proposed_type().as_str() != RDFS_CLASS {
            return Err(Error::invalid("type assertion object is not a class token"));
        }
        let asserted_type = Iri::new(object.source_spelling())?;
        if &asserted_type != subject.proposed_type() {
            return Err(Error::invalid(
                "type assertion does not match proposed endpoint type",
            ));
        }
        ontology.require_extraction_term(&asserted_type, OntologyTermKind::Class)?;
        if let Some(previous) = type_objects.insert(type_object.clone(), asserted_type.clone()) {
            if previous != asserted_type {
                return Err(Error::invalid("ambiguous ontology class token"));
            }
        }
    }
    if bundle
        .claims
        .iter()
        .any(|claim| type_objects.contains_key(&claim.subject))
    {
        return Err(Error::invalid("ontology class token used as claim subject"));
    }
    Ok(type_objects)
}

fn validate_endpoint_type_references(
    claim: &crate::candidates::AdvisoryClaim,
    bundle: &AdvisoryBundle,
    subject_type: &Iri,
    object_type: &Iri,
) -> Result<()> {
    let mut subject_covered = false;
    let mut object_covered = matches!(claim.object, CandidateObject::Literal(_));
    let mut unique = BTreeSet::new();
    for reference in &claim.endpoint_type_claims {
        if !unique.insert(reference) {
            return Err(Error::invalid("duplicate endpoint type claim reference"));
        }
        let referenced = bundle
            .claims
            .iter()
            .find(|candidate| &candidate.local_claim_id == reference)
            .ok_or_else(|| Error::invalid("unknown endpoint type claim"))?;
        if referenced.predicate.as_str() != RDF_TYPE
            || referenced.relation_type.as_str() != TYPE_ASSERTION_RELATION_TYPE
            || referenced.claim_type.as_str() != TYPE_ASSERTION_CLAIM_TYPE
        {
            return Err(Error::invalid("endpoint reference is not a type assertion"));
        }
        let CandidateObject::Entity(type_object) = &referenced.object else {
            return Err(Error::invalid("endpoint type assertion object"));
        };
        let asserted_type = bundle
            .entities
            .iter()
            .find(|entity| entity.local_id() == type_object)
            .ok_or_else(|| Error::invalid("endpoint type assertion object"))?;
        let asserted_type = Iri::new(asserted_type.source_spelling())?;
        let mut matched = false;
        if referenced.subject == claim.subject && &asserted_type == subject_type {
            subject_covered = true;
            matched = true;
        }
        if let CandidateObject::Entity(object) = &claim.object {
            if &referenced.subject == object && &asserted_type == object_type {
                object_covered = true;
                matched = true;
            }
        }
        if !matched {
            return Err(Error::invalid("unrelated endpoint type claim reference"));
        }
    }
    if !subject_covered || !object_covered {
        return Err(Error::invalid("missing explicit endpoint type claims"));
    }
    Ok(())
}

fn validate_temporal_support(
    claim: &crate::candidates::AdvisoryClaim,
    metadata: &crate::candidates::ClaimMetadata,
    bundle: &AdvisoryBundle,
) -> Result<()> {
    match (&claim.valid_time, &metadata.temporal_qualifier_claim) {
        (None, None) => Ok(()),
        (None, Some(_)) | (Some(_), None) => Err(Error::invalid("temporal qualifier mismatch")),
        (Some(valid_time), Some(reference)) => {
            if reference == &claim.local_claim_id {
                return Err(Error::invalid("self-supporting temporal qualifier"));
            }
            let canonical = Timestamp::parse(valid_time)?.canonical();
            if canonical.as_str() != valid_time {
                return Err(Error::invalid("non-canonical valid time"));
            }
            let supporting = bundle
                .claims
                .iter()
                .find(|candidate| &candidate.local_claim_id == reference)
                .ok_or_else(|| Error::invalid("unknown temporal qualifier claim"))?;
            let CandidateObject::Literal(literal) = &supporting.object else {
                return Err(Error::invalid("temporal qualifier is not a literal claim"));
            };
            if supporting.subject != claim.subject
                || literal.datatype().as_str() != XSD_DATETIME
                || literal.lexical() != valid_time
            {
                return Err(Error::invalid(
                    "temporal qualifier does not support valid time",
                ));
            }
            Ok(())
        }
    }
}

fn literal_value(value: &crate::candidates::TypedLiteral) -> Result<V> {
    let datatype = value.datatype().as_str();
    let scalar = if datatype == XSD_BOOLEAN {
        match value.lexical() {
            "true" | "1" => V::Bool(true),
            "false" | "0" => V::Bool(false),
            _ => return Err(Error::invalid("literal boolean")),
        }
    } else if datatype == XSD_INTEGER {
        let lexical = value.lexical();
        let unsigned = lexical
            .strip_prefix('+')
            .or_else(|| lexical.strip_prefix('-'))
            .unwrap_or(lexical);
        if unsigned.is_empty() || !unsigned.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::invalid("non-integral integer lexical form"));
        }
        V::Number(ExactNumber::parse(
            lexical.strip_prefix('+').unwrap_or(lexical),
        )?)
    } else if datatype == XSD_DECIMAL {
        let lexical = value.lexical();
        let unsigned = lexical
            .strip_prefix('+')
            .or_else(|| lexical.strip_prefix('-'))
            .unwrap_or(lexical);
        let mut point = false;
        let mut digits = 0usize;
        for byte in unsigned.bytes() {
            if byte == b'.' && !point {
                point = true;
            } else if byte.is_ascii_digit() {
                digits += 1;
            } else {
                return Err(Error::invalid("invalid decimal lexical form"));
            }
        }
        if digits == 0 {
            return Err(Error::invalid("invalid decimal lexical form"));
        }
        let mut parse_lexical = lexical.strip_prefix('+').unwrap_or(lexical).to_owned();
        if parse_lexical.starts_with("-.") {
            parse_lexical.insert(1, '0');
        } else if parse_lexical.starts_with('.') {
            parse_lexical.insert(0, '0');
        }
        if parse_lexical.ends_with('.') {
            parse_lexical.push('0');
        }
        V::Number(ExactNumber::parse(&parse_lexical)?)
    } else if datatype == XSD_DATETIME {
        let timestamp = Timestamp::parse(value.lexical())?;
        if timestamp.canonical() != value.lexical() {
            return Err(Error::invalid("non-canonical dateTime lexical form"));
        }
        V::string(value.lexical())
    } else if datatype == XSD_STRING || datatype == RDF_LANG_STRING {
        V::string(value.lexical())
    } else {
        return Err(Error::invalid("unsupported literal datatype"));
    };
    V::object([
        ("kind".into(), V::string("literal")),
        ("datatype".into(), V::string(datatype)),
        ("value".into(), scalar),
        (
            "language".into(),
            value.language().map(V::string).unwrap_or(V::Null),
        ),
    ])
}

fn ensure_connected(bundle: &AdvisoryBundle) -> Result<()> {
    let mut adjacency = BTreeMap::<&LocalId, BTreeSet<&LocalId>>::new();
    for claim in &bundle.claims {
        adjacency.entry(&claim.subject).or_default();
        if claim.predicate.as_str() == RDF_TYPE {
            continue;
        }
        if let CandidateObject::Entity(object) = &claim.object {
            adjacency.entry(&claim.subject).or_default().insert(object);
            adjacency.entry(object).or_default().insert(&claim.subject);
        }
    }
    let Some(start) = adjacency.keys().next().copied() else {
        return Err(Error::invalid("empty bundle graph"));
    };
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([start]);
    while let Some(entity) = queue.pop_front() {
        if !seen.insert(entity) {
            continue;
        }
        queue.extend(adjacency.get(entity).into_iter().flatten().copied());
    }
    if seen.len() != adjacency.len() {
        return Err(Error::invalid("disconnected claim bundle"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidates::{AdvisoryClaim, CandidateLimits, ClaimMetadata, EntityCandidate};
    use crate::coordinates::{LineCoordinate, LineSelection};
    use cdb_core::evidence::Utf8Span;
    use cdb_core::id::{AuthorityId, BackendId, GraphId, ResourceId, VersionId};
    use cdb_core::snapshot::GraphPin;

    struct Allow;
    impl OntologyAuthority for Allow {
        fn extraction_term(&self, iri: &Iri) -> Result<cdb_core::ontology_catalog::OntologyTerm> {
            use cdb_core::ontology_catalog::{OntologyTerm, VocabularyStatus};
            let person = Iri::new("urn:type:person").unwrap();
            let (kind, domains, ranges) = match iri.as_str() {
                "urn:type:person" => (OntologyTermKind::Class, BTreeSet::new(), BTreeSet::new()),
                BUSINESS_RELATION_TYPE | TYPE_ASSERTION_RELATION_TYPE => (
                    OntologyTermKind::RelationType,
                    BTreeSet::new(),
                    BTreeSet::new(),
                ),
                BUSINESS_CLAIM_TYPE | TYPE_ASSERTION_CLAIM_TYPE => (
                    OntologyTermKind::ClaimType,
                    BTreeSet::new(),
                    BTreeSet::new(),
                ),
                "urn:relation:knows" => (
                    OntologyTermKind::Property,
                    BTreeSet::from([person.clone()]),
                    BTreeSet::from([person]),
                ),
                _ => return Err(Error::invalid("unknown test term")),
            };
            OntologyTerm::new(
                iri.clone(),
                kind,
                VocabularyStatus::Canonical,
                true,
                BTreeSet::new(),
                domains,
                ranges,
            )
        }
    }
    struct Resolve;
    impl EntityResolver for Resolve {
        fn resolve(
            &self,
            _: &str,
            _: &ContentHash,
            _: &str,
            local: &str,
            _: &str,
            _: &Iri,
        ) -> Result<Iri> {
            Iri::new(format!("urn:entity:{local}"))
        }
    }
    fn capture() -> SnapshotRef {
        SnapshotRef::new(
            BackendId::new("fluree").unwrap(),
            GraphPin::new(
                AuthorityId::new("authority").unwrap(),
                GraphId::new("semantic").unwrap(),
                VersionId::new("1").unwrap(),
                ResourceId::new("cid").unwrap(),
            ),
        )
    }

    #[test]
    fn validates_exact_coordinates_and_mints_deterministic_ids() {
        let text = "Alice knows Bob.\n";
        let locator = Iri::new("file:///doc.txt").unwrap();
        let text_version = ContentHash::of_bytes(b"converter-bound-version");
        let map = CoordinateMap::issue(
            text,
            "attempt",
            "window",
            locator.clone(),
            text_version.clone(),
            ContentHash::of_bytes(text.as_bytes()),
            Utf8Span::new(0, text.len()).unwrap(),
        )
        .unwrap();
        let limits = CandidateLimits::default();
        let local = |value| LocalId::new(value, limits.max_local_id_bytes).unwrap();
        let type_iri = Iri::new("urn:type:person").unwrap();
        let advisory = AdvisoryBundle {
            local_bundle_id: local("bundle"),
            entities: vec![
                EntityCandidate::new(local("alice"), "Alice", type_iri.clone(), &limits).unwrap(),
                EntityCandidate::new(local("bob"), "Bob", type_iri.clone(), &limits).unwrap(),
                EntityCandidate::new(
                    local("person-type"),
                    type_iri.as_str(),
                    Iri::new(RDFS_CLASS).unwrap(),
                    &limits,
                )
                .unwrap(),
            ],
            claims: vec![
                AdvisoryClaim {
                    local_claim_id: local("claim"),
                    subject: local("alice"),
                    predicate: Iri::new("urn:relation:knows").unwrap(),
                    object: CandidateObject::Entity(local("bob")),
                    relation_type: Iri::new(BUSINESS_RELATION_TYPE).unwrap(),
                    claim_type: Iri::new(BUSINESS_CLAIM_TYPE).unwrap(),
                    endpoint_type_claims: vec![local("alice-type"), local("bob-type")],
                    confidence: Some("0.9".into()),
                    valid_time: None,
                },
                AdvisoryClaim {
                    local_claim_id: local("alice-type"),
                    subject: local("alice"),
                    predicate: Iri::new(RDF_TYPE).unwrap(),
                    object: CandidateObject::Entity(local("person-type")),
                    relation_type: Iri::new(TYPE_ASSERTION_RELATION_TYPE).unwrap(),
                    claim_type: Iri::new(TYPE_ASSERTION_CLAIM_TYPE).unwrap(),
                    endpoint_type_claims: vec![],
                    confidence: Some("0.9".into()),
                    valid_time: None,
                },
                AdvisoryClaim {
                    local_claim_id: local("bob-type"),
                    subject: local("bob"),
                    predicate: Iri::new(RDF_TYPE).unwrap(),
                    object: CandidateObject::Entity(local("person-type")),
                    relation_type: Iri::new(TYPE_ASSERTION_RELATION_TYPE).unwrap(),
                    claim_type: Iri::new(TYPE_ASSERTION_CLAIM_TYPE).unwrap(),
                    endpoint_type_claims: vec![],
                    confidence: Some("0.9".into()),
                    valid_time: None,
                },
            ],
            metadata: vec![
                ClaimMetadata {
                    local_claim_id: local("claim"),
                    locator: locator.clone(),
                    text_version: text_version.clone(),
                    coordinates: vec![LineCoordinate {
                        line_id: map.lines()[0].id.clone(),
                        selection: LineSelection::Range { start: 0, end: 15 },
                    }],
                    temporal_qualifier_claim: None,
                },
                ClaimMetadata {
                    local_claim_id: local("alice-type"),
                    locator: locator.clone(),
                    text_version: text_version.clone(),
                    coordinates: vec![LineCoordinate {
                        line_id: map.lines()[0].id.clone(),
                        selection: LineSelection::Range { start: 0, end: 5 },
                    }],
                    temporal_qualifier_claim: None,
                },
                ClaimMetadata {
                    local_claim_id: local("bob-type"),
                    locator: locator.clone(),
                    text_version: text_version.clone(),
                    coordinates: vec![LineCoordinate {
                        line_id: map.lines()[0].id.clone(),
                        selection: LineSelection::Range { start: 12, end: 15 },
                    }],
                    temporal_qualifier_claim: None,
                },
            ],
        };
        let make = || ValidationInput {
            extraction_run: ExtractionRunId::new("run").unwrap(),
            validation_capture: capture(),
            descriptor: V::object([("window".into(), V::string("window"))]).unwrap(),
            source_id: SourceId::new("source").unwrap(),
            document: text,
            attempt_id: "attempt",
            window_id: "window",
            coordinates: &map,
            max_spans_per_claim: 4,
            limits: Limits::default(),
        };
        let mut missing_endpoint_types = advisory.clone();
        missing_endpoint_types.claims[0]
            .endpoint_type_claims
            .clear();
        assert!(validate_bundle(missing_endpoint_types, make(), &Allow, &Resolve).is_err());
        let mut falsely_connected_by_shared_type = advisory.clone();
        falsely_connected_by_shared_type.claims.remove(0);
        falsely_connected_by_shared_type.metadata.remove(0);
        assert!(
            validate_bundle(falsely_connected_by_shared_type, make(), &Allow, &Resolve).is_err()
        );
        let mut false_type_reference = advisory.clone();
        false_type_reference.claims[1].predicate = Iri::new("urn:relation:knows").unwrap();
        assert!(validate_bundle(false_type_reference, make(), &Allow, &Resolve).is_err());
        let mut unsupported_valid_time = advisory.clone();
        unsupported_valid_time.claims[0].valid_time = Some("2026-09-22T00:00:00.000Z".into());
        assert!(validate_bundle(unsupported_valid_time, make(), &Allow, &Resolve).is_err());
        let first = validate_bundle(advisory.clone(), make(), &Allow, &Resolve).unwrap();
        let second = validate_bundle(advisory, make(), &Allow, &Resolve).unwrap();
        assert_eq!(first.projection(), second.projection());
        assert_eq!(first.claims().len(), 3);
        assert!(
            first.claims()[0].lineage().sources()[0]
                .verify(text.as_bytes())
                .unwrap()
                == cdb_core::evidence::VerificationOutcome::Verified
        );
    }

    #[test]
    fn literal_lexical_spaces_are_closed() {
        let limits = CandidateLimits::default();
        let literal = |lexical: &str, datatype: &str| {
            crate::candidates::TypedLiteral::new(
                lexical,
                Iri::new(datatype).unwrap(),
                None,
                &limits,
            )
            .unwrap()
        };
        assert!(literal_value(&literal("1.5", XSD_INTEGER)).is_err());
        assert!(literal_value(&literal("1e2", XSD_DECIMAL)).is_err());
        assert!(literal_value(&literal(".", XSD_DECIMAL)).is_err());
        assert!(literal_value(&literal("2026-09-22", XSD_DATETIME)).is_err());
        assert!(literal_value(&literal("opaque", "urn:datatype:unknown")).is_err());
        assert!(literal_value(&literal("42", XSD_INTEGER)).is_ok());
        assert!(literal_value(&literal("+.5", XSD_DECIMAL)).is_ok());
        assert!(literal_value(&literal("1.", XSD_DECIMAL)).is_ok());
    }
}
