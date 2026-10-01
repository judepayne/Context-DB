//! Backend-neutral, capture-bound ontology catalog values used by acquisition.

use crate::id::{ContentHash, Iri};
use crate::snapshot::SnapshotRef;
use crate::{CanonicalValue as V, Error, Limits, Result};
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
pub enum VocabularyStatus {
    Canonical,
    PermittedExtension,
    Discouraged,
    Deprecated,
    NotEligible,
}
impl VocabularyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::PermittedExtension => "permitted_extension",
            Self::Discouraged => "discouraged",
            Self::Deprecated => "deprecated",
            Self::NotEligible => "not_eligible",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OntologyTermKind {
    Class,
    Property,
    RelationType,
    ClaimType,
    Datatype,
}
impl OntologyTermKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Property => "property",
            Self::RelationType => "relation_type",
            Self::ClaimType => "claim_type",
            Self::Datatype => "datatype",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OntologyTerm {
    iri: Iri,
    kind: OntologyTermKind,
    status: VocabularyStatus,
    extraction_eligible: bool,
    super_terms: BTreeSet<Iri>,
    domains: BTreeSet<Iri>,
    ranges: BTreeSet<Iri>,
}
impl OntologyTerm {
    pub fn new(
        iri: Iri,
        kind: OntologyTermKind,
        status: VocabularyStatus,
        extraction_eligible: bool,
        super_terms: BTreeSet<Iri>,
        domains: BTreeSet<Iri>,
        ranges: BTreeSet<Iri>,
    ) -> Result<Self> {
        if extraction_eligible
            && matches!(
                status,
                VocabularyStatus::Discouraged | VocabularyStatus::Deprecated
            )
        {
            return Err(Error::invalid("noncanonical extraction term"));
        }
        Ok(Self {
            iri,
            kind,
            status,
            extraction_eligible,
            super_terms,
            domains,
            ranges,
        })
    }
    pub fn iri(&self) -> &Iri {
        &self.iri
    }
    pub fn kind(&self) -> OntologyTermKind {
        self.kind
    }
    pub fn status(&self) -> VocabularyStatus {
        self.status
    }
    pub fn extraction_eligible(&self) -> bool {
        self.extraction_eligible
    }
    pub fn super_terms(&self) -> &BTreeSet<Iri> {
        &self.super_terms
    }
    pub fn domains(&self) -> &BTreeSet<Iri> {
        &self.domains
    }
    pub fn ranges(&self) -> &BTreeSet<Iri> {
        &self.ranges
    }
    pub fn projection(&self) -> V {
        let iris = |values: &BTreeSet<Iri>| {
            V::Array(values.iter().map(|v| V::string(v.as_str())).collect())
        };
        obj([
            ("iri", V::string(self.iri.as_str())),
            ("kind", V::string(self.kind.as_str())),
            ("status", V::string(self.status.as_str())),
            ("extraction_eligible", V::Bool(self.extraction_eligible)),
            ("super_terms", iris(&self.super_terms)),
            ("domains", iris(&self.domains)),
            ("ranges", iris(&self.ranges)),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OntologyCatalogIdentity {
    capture: SnapshotRef,
    profile_identity: String,
    profile_root: ContentHash,
    catalog_root: ContentHash,
    semantic_coverage_root: ContentHash,
    caveat_root: ContentHash,
}
impl OntologyCatalogIdentity {
    pub fn new(
        capture: SnapshotRef,
        profile_identity: impl Into<String>,
        profile_root: ContentHash,
        catalog_root: ContentHash,
        semantic_coverage_root: ContentHash,
        caveat_root: ContentHash,
    ) -> Result<Self> {
        let profile_identity = profile_identity.into();
        if profile_identity != crate::recording_v4::ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID
            && profile_identity != crate::recording_v5::CURRENT_ACQUISITION_PROFILE_ID
        {
            return Err(Error::invalid("acquisition ontology profile"));
        }
        Ok(Self {
            capture,
            profile_identity,
            profile_root,
            catalog_root,
            semantic_coverage_root,
            caveat_root,
        })
    }
    pub fn capture(&self) -> &SnapshotRef {
        &self.capture
    }
    pub fn profile_identity(&self) -> &str {
        &self.profile_identity
    }
    pub fn catalog_root(&self) -> &ContentHash {
        &self.catalog_root
    }
    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql-ontology-catalog/v1")),
            ("capture", self.capture.projection()),
            ("profile_identity", V::string(&self.profile_identity)),
            ("profile_root", V::string(self.profile_root.as_str())),
            ("catalog_root", V::string(self.catalog_root.as_str())),
            (
                "semantic_coverage_root",
                V::string(self.semantic_coverage_root.as_str()),
            ),
            ("caveat_root", V::string(self.caveat_root.as_str())),
        ])
    }
    pub fn verify_terms(&self, terms: &[OntologyTerm], limits: Limits) -> Result<()> {
        let value = V::Array(terms.iter().map(OntologyTerm::projection).collect());
        if ContentHash::of_bytes(&value.canonical_bytes(limits)?) != self.catalog_root {
            return Err(Error::invalid("ontology catalog root"));
        }
        Ok(())
    }
}
