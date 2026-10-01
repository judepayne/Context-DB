//! Closed acquisition-v2 endpoint-classification metadata.
//!
//! This metadata is a frozen annotation on a claim. It is not evidence, an
//! authorization grant, or a substitute for explicit `rdf:type` assertions.

use crate::{
    claim::{CandidateClaim, ClaimObject},
    id::{ContentHash, Iri, ResourceId},
    value::obj,
    CanonicalValue as V, Error, Result,
};

pub const EXTENSION_KEY: &str = "ctxql.acquisition.classification/v2";
pub const REPRESENTATIVE_ALGORITHM: &str =
    "ctxql-acquisition-class-representative/lexicographic-canonical-iri/v1";
pub const UNCLASSIFIED_ENTITY: &str = "https://ctxql.example/acquisition/v2/UnclassifiedEntity";
pub const PROVISIONAL_ENTITY: &str = "https://ctxql.example/acquisition/v2/ProvisionalEntity";
pub const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
pub const RDFS_CLASS: &str = "http://www.w3.org/2000/01/rdf-schema#Class";
const MAX_CLASSES_PER_ENDPOINT: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ClassificationOrigin {
    Extracted,
    Established,
}

impl ClassificationOrigin {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "extracted" => Ok(Self::Extracted),
            "established" => Ok(Self::Established),
            _ => Err(Error::invalid("classification origin")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Extracted => "extracted",
            Self::Established => "established",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ClassificationRef {
    iri: Iri,
    origin: ClassificationOrigin,
    reference: ResourceId,
}

impl ClassificationRef {
    pub fn new(iri: Iri, origin: ClassificationOrigin, reference: ResourceId) -> Self {
        Self {
            iri,
            origin,
            reference,
        }
    }

    fn from_value(value: &V) -> Result<Self> {
        value.closed(&["iri", "origin", "reference"], &[])?;
        Ok(Self::new(
            Iri::new(value.field("iri")?.as_str()?)?,
            ClassificationOrigin::parse(value.field("origin")?.as_str()?)?,
            ResourceId::new(value.field("reference")?.as_str()?)?,
        ))
    }

    pub fn projection(&self) -> V {
        obj([
            ("iri", V::string(self.iri.as_str())),
            ("origin", V::string(self.origin.as_str())),
            ("reference", V::string(self.reference.as_str())),
        ])
    }

    pub fn iri(&self) -> &Iri {
        &self.iri
    }

    pub fn origin(&self) -> ClassificationOrigin {
        self.origin
    }

    pub fn reference(&self) -> &ResourceId {
        &self.reference
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointClassificationStatus {
    Classified,
    Unclassified,
    Provisional,
}

impl EndpointClassificationStatus {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "classified" => Ok(Self::Classified),
            "unclassified" => Ok(Self::Unclassified),
            "provisional" => Ok(Self::Provisional),
            _ => Err(Error::invalid("classification endpoint status")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Classified => "classified",
            Self::Unclassified => "unclassified",
            Self::Provisional => "provisional",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointClassification {
    status: EndpointClassificationStatus,
    classes: Vec<ClassificationRef>,
}

impl EndpointClassification {
    pub fn new(
        status: EndpointClassificationStatus,
        mut classes: Vec<ClassificationRef>,
    ) -> Result<Self> {
        classes.sort();
        classes.dedup();
        let endpoint = Self { status, classes };
        endpoint.validate()?;
        Ok(endpoint)
    }

    fn from_value(value: &V) -> Result<Self> {
        value.closed(&["status", "classes"], &[])?;
        let status = EndpointClassificationStatus::parse(value.field("status")?.as_str()?)?;
        let classes = value
            .field("classes")?
            .as_array()?
            .iter()
            .map(ClassificationRef::from_value)
            .collect::<Result<Vec<_>>>()?;
        let endpoint = Self { status, classes };
        endpoint.validate()?;
        Ok(endpoint)
    }

    fn validate(&self) -> Result<()> {
        if self.classes.len() > MAX_CLASSES_PER_ENDPOINT {
            return Err(Error::limit());
        }
        if self.classes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::invalid("classification classes sorted unique"));
        }
        match self.status {
            EndpointClassificationStatus::Classified if self.classes.is_empty() => {
                Err(Error::invalid("classified endpoint requires classes"))
            }
            EndpointClassificationStatus::Unclassified
            | EndpointClassificationStatus::Provisional
                if !self.classes.is_empty() =>
            {
                Err(Error::invalid("non-classified endpoint has classes"))
            }
            _ => Ok(()),
        }
    }

    pub fn projection(&self) -> V {
        obj([
            ("status", V::string(self.status.as_str())),
            (
                "classes",
                V::Array(
                    self.classes
                        .iter()
                        .map(ClassificationRef::projection)
                        .collect(),
                ),
            ),
        ])
    }

    pub fn status(&self) -> EndpointClassificationStatus {
        self.status
    }

    pub fn classes(&self) -> &[ClassificationRef] {
        &self.classes
    }

    pub fn representative(&self) -> &str {
        match self.status {
            EndpointClassificationStatus::Classified => self
                .classes
                .iter()
                .map(|entry| entry.iri.as_str())
                .min()
                .expect("classified endpoint has a class"),
            EndpointClassificationStatus::Unclassified => UNCLASSIFIED_ENTITY,
            EndpointClassificationStatus::Provisional => PROVISIONAL_ENTITY,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationMetadata {
    frozen_context_root: ContentHash,
    subject: EndpointClassification,
    object: EndpointClassification,
}

impl ClassificationMetadata {
    pub fn new(
        frozen_context_root: ContentHash,
        subject: EndpointClassification,
        object: EndpointClassification,
    ) -> Self {
        Self {
            frozen_context_root,
            subject,
            object,
        }
    }

    pub fn from_value(value: &V) -> Result<Self> {
        value.closed(
            &[
                "representative_algorithm",
                "frozen_context_root",
                "subject",
                "object",
            ],
            &[],
        )?;
        if value.field("representative_algorithm")?.as_str()? != REPRESENTATIVE_ALGORITHM {
            return Err(Error::invalid("classification representative algorithm"));
        }
        Ok(Self::new(
            ContentHash::parse(value.field("frozen_context_root")?.as_str()?)?,
            EndpointClassification::from_value(value.field("subject")?)?,
            EndpointClassification::from_value(value.field("object")?)?,
        ))
    }

    pub fn projection(&self) -> V {
        obj([
            (
                "representative_algorithm",
                V::string(REPRESENTATIVE_ALGORITHM),
            ),
            (
                "frozen_context_root",
                V::string(self.frozen_context_root.as_str()),
            ),
            ("subject", self.subject.projection()),
            ("object", self.object.projection()),
        ])
    }

    pub fn subject(&self) -> &EndpointClassification {
        &self.subject
    }

    pub fn object(&self) -> &EndpointClassification {
        &self.object
    }

    pub fn frozen_context_root(&self) -> &ContentHash {
        &self.frozen_context_root
    }

    /// References to separately authorized established-class support claims.
    /// Durable acquisition lowering must use the admitted supporting claim ID
    /// for `established`; extracted component references are capture-local
    /// provenance and are not grants.
    pub fn established_supports(&self) -> impl Iterator<Item = &ResourceId> {
        self.subject
            .classes
            .iter()
            .chain(self.object.classes.iter())
            .filter(|entry| entry.origin == ClassificationOrigin::Established)
            .map(|entry| &entry.reference)
    }

    pub fn validate_claim(&self, claim: &CandidateClaim) -> Result<()> {
        validate_entity_representative(&self.subject, claim.subject_type().as_str())?;
        if claim.relation().as_str() == RDF_TYPE {
            let ClaimObject::Entity(_) = claim.object() else {
                return Err(Error::invalid("RDF type claim object"));
            };
            validate_non_entity(&self.object)?;
            if claim.object_type().as_str() != RDFS_CLASS {
                return Err(Error::invalid("RDF type object metadata"));
            }
        } else {
            match claim.object() {
                ClaimObject::Entity(_) => {
                    validate_entity_representative(&self.object, claim.object_type().as_str())?;
                }
                ClaimObject::Literal(literal) => {
                    validate_non_entity(&self.object)?;
                    if claim.object_type() != literal.datatype() {
                        return Err(Error::invalid("literal classification object type"));
                    }
                }
            }
        }
        Ok(())
    }
}

fn validate_entity_representative(endpoint: &EndpointClassification, actual: &str) -> Result<()> {
    if endpoint.representative() != actual {
        return Err(Error::invalid("classification representative mismatch"));
    }
    Ok(())
}

fn validate_non_entity(endpoint: &EndpointClassification) -> Result<()> {
    if endpoint.status != EndpointClassificationStatus::Unclassified || !endpoint.classes.is_empty()
    {
        return Err(Error::invalid("non-entity classification metadata"));
    }
    Ok(())
}
