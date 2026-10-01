use crate::coordinates::LineCoordinate;
use cdb_core::id::{ContentHash, Iri};
use cdb_core::{CanonicalValue as V, Error, Limits, Result};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LocalId(String);
impl LocalId {
    pub fn new(value: impl Into<String>, max_bytes: usize) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
            return Err(Error::invalid("invalid bounded local ID"));
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateLimits {
    pub max_local_id_bytes: usize,
    pub max_source_spelling_bytes: usize,
    pub max_literal_bytes: usize,
    pub max_claims_per_bundle: usize,
    pub max_metadata_per_bundle: usize,
    pub max_spans_per_claim: usize,
}
impl Default for CandidateLimits {
    fn default() -> Self {
        Self {
            max_local_id_bytes: 128,
            max_source_spelling_bytes: 1024,
            max_literal_bytes: 16 * 1024,
            max_claims_per_bundle: 64,
            max_metadata_per_bundle: 64,
            max_spans_per_claim: 16,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityCandidate {
    local_id: LocalId,
    source_spelling: String,
    proposed_type: Iri,
}
impl EntityCandidate {
    pub fn new(
        local_id: LocalId,
        source_spelling: impl Into<String>,
        proposed_type: Iri,
        limits: &CandidateLimits,
    ) -> Result<Self> {
        let source_spelling = source_spelling.into();
        bounded(
            &source_spelling,
            limits.max_source_spelling_bytes,
            "source spelling",
        )?;
        Ok(Self {
            local_id,
            source_spelling,
            proposed_type,
        })
    }
    pub fn local_id(&self) -> &LocalId {
        &self.local_id
    }
    pub fn source_spelling(&self) -> &str {
        &self.source_spelling
    }
    pub fn proposed_type(&self) -> &Iri {
        &self.proposed_type
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedLiteral {
    lexical: String,
    datatype: Iri,
    language: Option<String>,
}
impl TypedLiteral {
    pub fn new(
        lexical: impl Into<String>,
        datatype: Iri,
        language: Option<String>,
        limits: &CandidateLimits,
    ) -> Result<Self> {
        let lexical = lexical.into();
        bounded(&lexical, limits.max_literal_bytes, "literal")?;
        if let Some(tag) = &language {
            if tag.len() > 63 || tag != &tag.to_ascii_lowercase() || !valid_language_tag(tag) {
                return Err(Error::invalid("canonical lowercase language tag required"));
            }
        }
        Ok(Self {
            lexical,
            datatype,
            language,
        })
    }
    pub fn lexical(&self) -> &str {
        &self.lexical
    }
    pub fn datatype(&self) -> &Iri {
        &self.datatype
    }
    pub fn language(&self) -> Option<&str> {
        self.language.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateObject {
    Entity(LocalId),
    Literal(TypedLiteral),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvisoryClaim {
    pub local_claim_id: LocalId,
    pub subject: LocalId,
    pub predicate: Iri,
    pub object: CandidateObject,
    pub relation_type: Iri,
    pub claim_type: Iri,
    pub endpoint_type_claims: Vec<LocalId>,
    pub confidence: Option<String>,
    pub valid_time: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimMetadata {
    pub local_claim_id: LocalId,
    pub locator: Iri,
    pub text_version: ContentHash,
    pub coordinates: Vec<LineCoordinate>,
    pub temporal_qualifier_claim: Option<LocalId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvisoryBundle {
    pub local_bundle_id: LocalId,
    pub entities: Vec<EntityCandidate>,
    pub claims: Vec<AdvisoryClaim>,
    pub metadata: Vec<ClaimMetadata>,
}

impl AdvisoryBundle {
    pub fn validate_shape(&self, limits: &CandidateLimits) -> Result<()> {
        if self.claims.is_empty()
            || self.claims.len() > limits.max_claims_per_bundle
            || self.metadata.len() > limits.max_metadata_per_bundle
        {
            return Err(Error::limit());
        }
        unique(self.entities.iter().map(|x| x.local_id()))?;
        unique(self.claims.iter().map(|x| &x.local_claim_id))?;
        unique(self.metadata.iter().map(|x| &x.local_claim_id))?;
        let entities: BTreeSet<_> = self.entities.iter().map(|x| x.local_id()).collect();
        let claims: BTreeSet<_> = self.claims.iter().map(|x| &x.local_claim_id).collect();
        let metadata: BTreeSet<_> = self.metadata.iter().map(|x| &x.local_claim_id).collect();
        if claims != metadata {
            return Err(Error::invalid(
                "each claim requires exactly one metadata block",
            ));
        }
        for claim in &self.claims {
            if !entities.contains(&claim.subject) {
                return Err(Error::invalid("unresolved subject"));
            }
            if let CandidateObject::Entity(id) = &claim.object {
                if !entities.contains(id) {
                    return Err(Error::invalid("unresolved object"));
                }
            }
            if claim
                .endpoint_type_claims
                .iter()
                .any(|id| !claims.contains(id))
            {
                return Err(Error::invalid("unresolved endpoint type claim"));
            }
        }
        for item in &self.metadata {
            if item.coordinates.is_empty() || item.coordinates.len() > limits.max_spans_per_claim {
                return Err(Error::limit());
            }
            if item
                .temporal_qualifier_claim
                .as_ref()
                .is_some_and(|id| !claims.contains(id))
            {
                return Err(Error::invalid("unresolved temporal qualifier claim"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractionIdentity {
    fields: BTreeMap<String, String>,
}
impl ExtractionIdentity {
    pub fn new(fields: impl IntoIterator<Item = (String, String)>) -> Result<Self> {
        let mut out = BTreeMap::new();
        for (key, value) in fields {
            bounded(&key, 128, "identity key")?;
            bounded(&value, 4096, "identity value")?;
            if out.insert(key, value).is_some() {
                return Err(Error::invalid("duplicate identity field"));
            }
        }
        if out.is_empty() {
            return Err(Error::invalid("empty extraction identity"));
        }
        Ok(Self { fields: out })
    }
    pub fn root(&self) -> Result<ContentHash> {
        let payload = V::object(self.fields.iter().map(|(k, v)| (k.clone(), V::string(v))))?;
        Ok(ContentHash::of_bytes(
            &payload.canonical_bytes(Limits::default())?,
        ))
    }
}

fn unique<'a>(values: impl Iterator<Item = &'a LocalId>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(Error::invalid("duplicate local ID"));
        }
    }
    Ok(())
}

fn valid_language_tag(tag: &str) -> bool {
    const GRANDFATHERED: &[&str] = &[
        "art-lojban",
        "cel-gaulish",
        "en-gb-oed",
        "i-ami",
        "i-bnn",
        "i-default",
        "i-enochian",
        "i-hak",
        "i-klingon",
        "i-lux",
        "i-mingo",
        "i-navajo",
        "i-pwn",
        "i-tao",
        "i-tay",
        "i-tsu",
        "no-bok",
        "no-nyn",
        "sgn-be-fr",
        "sgn-be-nl",
        "sgn-ch-de",
        "zh-guoyu",
        "zh-hakka",
        "zh-min",
        "zh-min-nan",
        "zh-xiang",
    ];
    if GRANDFATHERED.contains(&tag) {
        return true;
    }
    let parts = tag.split('-').collect::<Vec<_>>();
    if parts.iter().any(|part| {
        part.is_empty()
            || part.len() > 8
            || !part
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    }) {
        return false;
    }
    if parts.first() == Some(&"x") {
        return parts.len() > 1;
    }
    let alpha = |part: &str| part.bytes().all(|byte| byte.is_ascii_lowercase());
    let mut cursor = 0;
    let Some(language) = parts.get(cursor).copied() else {
        return false;
    };
    if !alpha(language) || !(2..=8).contains(&language.len()) {
        return false;
    }
    cursor += 1;
    if language.len() <= 3 {
        let mut extlangs = 0;
        while extlangs < 3
            && parts
                .get(cursor)
                .is_some_and(|part| part.len() == 3 && alpha(part))
        {
            cursor += 1;
            extlangs += 1;
        }
    }
    if parts
        .get(cursor)
        .is_some_and(|part| part.len() == 4 && alpha(part))
    {
        cursor += 1;
    }
    if parts.get(cursor).is_some_and(|part| {
        (part.len() == 2 && alpha(part))
            || (part.len() == 3 && part.bytes().all(|byte| byte.is_ascii_digit()))
    }) {
        cursor += 1;
    }
    let mut variants = BTreeSet::new();
    while parts.get(cursor).is_some_and(|part| {
        (5..=8).contains(&part.len()) || (part.len() == 4 && part.as_bytes()[0].is_ascii_digit())
    }) {
        if !variants.insert(parts[cursor]) {
            return false;
        }
        cursor += 1;
    }
    let mut extensions = BTreeSet::new();
    while parts.get(cursor).is_some_and(|part| {
        part.len() == 1 && *part != "x" && part.as_bytes()[0].is_ascii_alphanumeric()
    }) {
        if !extensions.insert(parts[cursor]) {
            return false;
        }
        cursor += 1;
        let start = cursor;
        while parts
            .get(cursor)
            .is_some_and(|part| (2..=8).contains(&part.len()))
        {
            cursor += 1;
        }
        if cursor == start {
            return false;
        }
    }
    if parts.get(cursor) == Some(&"x") {
        cursor += 1;
        let start = cursor;
        while parts
            .get(cursor)
            .is_some_and(|part| (1..=8).contains(&part.len()))
        {
            cursor += 1;
        }
        if cursor == start {
            return false;
        }
    }
    cursor == parts.len()
}

fn bounded(value: &str, max: usize, what: &str) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(Error::invalid(format!("invalid bounded {what}")))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_identity_is_order_independent_and_mutation_sensitive() {
        let a =
            ExtractionIdentity::new([("model".into(), "m".into()), ("capture".into(), "c".into())])
                .unwrap();
        let b =
            ExtractionIdentity::new([("capture".into(), "c".into()), ("model".into(), "m".into())])
                .unwrap();
        let c = ExtractionIdentity::new([
            ("capture".into(), "c".into()),
            ("model".into(), "other".into()),
        ])
        .unwrap();
        assert_eq!(a.root().unwrap(), b.root().unwrap());
        assert_ne!(a.root().unwrap(), c.root().unwrap());
    }
    #[test]
    fn bounds_and_language_are_closed() {
        let limits = CandidateLimits::default();
        assert!(LocalId::new("", limits.max_local_id_bytes).is_err());
        let datatype = Iri::new("urn:type:string").unwrap();
        for invalid in ["EN", "-", "en-", "1en", "en--gb", "en-a"] {
            assert!(
                TypedLiteral::new("x", datatype.clone(), Some(invalid.into()), &limits).is_err()
            );
        }
        for valid in ["en", "en-gb", "zh-hant-tw", "de-ch-1901", "x-private"] {
            assert!(TypedLiteral::new("x", datatype.clone(), Some(valid.into()), &limits).is_ok());
        }
    }
}
