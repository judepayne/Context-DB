//! Revision-bound Gate F compatibility profile for the selected direct reasoner.
//!
//! This is deliberately narrower than OWL 2 RL. It describes only constructs
//! exercised by the direct `reason_owl2rl` path at the pinned Fluree revision.

use crate::authorized_view::{framed_root, quad_root, ExactTerm, SourceQuad};
use cdb_core::id::ContentHash;
use std::collections::BTreeSet;

pub const ONTOLOGY_PROFILE_ID: &str =
    "ctxql-ontology-profile/fluree-4.2-603974fad5c13efed9d147d214d613849fb43c73/v1";

const RDF: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
const RDFS: &str = "http://www.w3.org/2000/01/rdf-schema#";
const OWL: &str = "http://www.w3.org/2002/07/owl#";
const F: &str = "https://ns.flur.ee/db#";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OntologyMemberClass {
    SupportedPremise,
    HarmlessMetadata,
    UnsupportedSemantic,
    MalformedReserved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OntologyProfileResult {
    pub identity: &'static str,
    pub supported: BTreeSet<SourceQuad>,
    pub harmless: BTreeSet<SourceQuad>,
    pub full_bundle_root: ContentHash,
    pub result_root: ContentHash,
}

/// Classify a complete, already-authorized schema/import bundle. Application
/// vocabulary is intentionally open; only reserved vocabulary receives profile
/// semantics. Unsupported semantics and malformed reserved structures fail
/// before E0 can seal a manifest.
pub fn classify_ontology_bundle(
    bundle: &BTreeSet<SourceQuad>,
) -> Result<OntologyProfileResult, String> {
    let mut supported = BTreeSet::new();
    let mut harmless = BTreeSet::new();
    for quad in bundle {
        match classify_member(quad) {
            OntologyMemberClass::SupportedPremise => {
                supported.insert(quad.clone());
            }
            OntologyMemberClass::HarmlessMetadata => {
                harmless.insert(quad.clone());
            }
            OntologyMemberClass::UnsupportedSemantic => {
                return Err("ontology_profile_unsupported".into());
            }
            OntologyMemberClass::MalformedReserved => {
                return Err("ontology_configuration_invalid".into());
            }
        }
    }
    let full_bundle_root = quad_root(bundle);
    let supported_root = quad_root(&supported);
    let harmless_root = quad_root(&harmless);
    let counts = format!("{}:{}:{}", bundle.len(), supported.len(), harmless.len());
    let result_root = framed_root(
        "ctxql-ontology-profile-result/v1",
        [
            ("profile", ONTOLOGY_PROFILE_ID),
            ("full-bundle", full_bundle_root.as_str()),
            ("supported", supported_root.as_str()),
            ("harmless", harmless_root.as_str()),
            ("counts", counts.as_str()),
        ],
    );
    Ok(OntologyProfileResult {
        identity: ONTOLOGY_PROFILE_ID,
        supported,
        harmless,
        full_bundle_root,
        result_root,
    })
}

pub fn classify_member(quad: &SourceQuad) -> OntologyMemberClass {
    let object_iri = match &quad.object {
        ExactTerm::Iri(value) => Some(value.as_str()),
        ExactTerm::ScopedBlankNode(_) | ExactTerm::Literal { .. } => None,
    };
    let reserved_object = object_iri.is_some_and(is_reserved);
    let reserved_subject = quad.subject_iri().is_some_and(is_reserved);
    if quad.subject_iri().is_none() || matches!(quad.object, ExactTerm::ScopedBlankNode(_)) {
        return OntologyMemberClass::UnsupportedSemantic;
    }

    if quad.predicate == RDF_TYPE {
        let Some(object) = object_iri else {
            return OntologyMemberClass::MalformedReserved;
        };
        return match object {
            // Direct 4.2 OWL2-RL property-characteristic rules.
            "http://www.w3.org/2002/07/owl#SymmetricProperty"
            | "http://www.w3.org/2002/07/owl#TransitiveProperty"
            | "http://www.w3.org/2002/07/owl#FunctionalProperty"
            | "http://www.w3.org/2002/07/owl#InverseFunctionalProperty" => {
                OntologyMemberClass::SupportedPremise
            }
            // Declarations do not feed the selected rules.
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#Property"
            | "http://www.w3.org/2000/01/rdf-schema#Class"
            | "http://www.w3.org/2002/07/owl#Class"
            | "http://www.w3.org/2002/07/owl#ObjectProperty"
            | "http://www.w3.org/2002/07/owl#DatatypeProperty"
            | "http://www.w3.org/2002/07/owl#AnnotationProperty" => {
                OntologyMemberClass::HarmlessMetadata
            }
            // Structural declaration retained so a metadata-empty source or
            // imported named graph still exists in the private schema bundle.
            "http://www.w3.org/2002/07/owl#Ontology" => OntologyMemberClass::SupportedPremise,
            // A type assertion against an application class is a supported
            // schema premise; unknown application IRIs are not allowlisted.
            value if !is_reserved(value) && !reserved_subject => {
                OntologyMemberClass::SupportedPremise
            }
            _ => OntologyMemberClass::UnsupportedSemantic,
        };
    }

    match quad.predicate.as_str() {
        "http://www.w3.org/2000/01/rdf-schema#subClassOf"
        | "http://www.w3.org/2000/01/rdf-schema#subPropertyOf"
        | "http://www.w3.org/2000/01/rdf-schema#domain"
        | "http://www.w3.org/2000/01/rdf-schema#range"
        | "http://www.w3.org/2002/07/owl#inverseOf"
        | "http://www.w3.org/2002/07/owl#equivalentClass"
        | "http://www.w3.org/2002/07/owl#sameAs"
        | "http://www.w3.org/2002/07/owl#imports" => {
            if object_iri.is_some() {
                OntologyMemberClass::SupportedPremise
            } else {
                OntologyMemberClass::MalformedReserved
            }
        }
        // The pinned direct RL materializer does not consume this construct;
        // it exists only in the separate OWL-QL query rewriter.
        "http://www.w3.org/2002/07/owl#equivalentProperty" => {
            if object_iri.is_some() {
                OntologyMemberClass::UnsupportedSemantic
            } else {
                OntologyMemberClass::MalformedReserved
            }
        }
        "http://www.w3.org/2000/01/rdf-schema#label"
        | "http://www.w3.org/2000/01/rdf-schema#comment"
        | "http://www.w3.org/2000/01/rdf-schema#seeAlso"
        | "http://www.w3.org/2000/01/rdf-schema#isDefinedBy"
        | "http://www.w3.org/2002/07/owl#versionInfo"
        | "http://www.w3.org/2002/07/owl#versionIRI"
        | "http://www.w3.org/2002/07/owl#priorVersion"
        | "http://www.w3.org/2002/07/owl#backwardCompatibleWith"
        | "http://www.w3.org/2002/07/owl#incompatibleWith"
        | "http://www.w3.org/2002/07/owl#deprecated" => OntologyMemberClass::HarmlessMetadata,
        predicate if is_reserved(predicate) => OntologyMemberClass::UnsupportedSemantic,
        // Reserved terms hidden behind application predicates still carry
        // reserved meaning (notably restrictions/list heads) and fail closed.
        _ if reserved_object || reserved_subject => OntologyMemberClass::UnsupportedSemantic,
        _ => OntologyMemberClass::SupportedPremise,
    }
}

fn is_reserved(value: &str) -> bool {
    value.starts_with(RDF)
        || value.starts_with(RDFS)
        || value.starts_with(OWL)
        || value.starts_with(F)
}
