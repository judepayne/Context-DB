use crate::evidence::Lineage;
use crate::id::*;
use crate::value::obj;
use crate::{CanonicalValue as V, Error, ExactNumber, Result, Timestamp};
use std::cmp::Ordering;
const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
const LANG: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedLiteral {
    datatype: Iri,
    value: V,
    language: Option<String>,
}
impl TypedLiteral {
    pub fn new(datatype: Iri, value: V, language: Option<String>) -> Result<Self> {
        let dt = datatype.as_str();
        if let Some(l) = &language {
            if dt != LANG
                || l.is_empty()
                || !l
                    .split('-')
                    .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_alphanumeric()))
                || !l.as_bytes()[0].is_ascii_alphabetic()
            {
                return Err(Error::invalid("literal language"));
            }
        }
        if dt == LANG {
            if language.is_none() {
                return Err(Error::invalid("langString requires language"));
            }
            value.as_str()?;
        } else if let Some(local) = dt.strip_prefix(XSD) {
            match local {
                "string" => {
                    value.as_str()?;
                }
                "boolean" => {
                    value.as_bool()?;
                }
                "integer" | "long" | "int" | "short" | "byte" | "unsignedLong" | "unsignedInt"
                | "unsignedShort" | "unsignedByte" | "nonNegativeInteger" | "positiveInteger"
                | "nonPositiveInteger" | "negativeInteger" => {
                    let n = value.as_number()?;
                    if !n.is_integer() {
                        return Err(Error::invalid("integer datatype"));
                    }
                    let (min, max) = match local {
                        "long" => (Some("-9223372036854775808"), Some("9223372036854775807")),
                        "int" => (Some("-2147483648"), Some("2147483647")),
                        "short" => (Some("-32768"), Some("32767")),
                        "byte" => (Some("-128"), Some("127")),
                        "unsignedLong" => (Some("0"), Some("18446744073709551615")),
                        "unsignedInt" => (Some("0"), Some("4294967295")),
                        "unsignedShort" => (Some("0"), Some("65535")),
                        "unsignedByte" => (Some("0"), Some("255")),
                        "nonNegativeInteger" => (Some("0"), None),
                        "positiveInteger" => (Some("1"), None),
                        "nonPositiveInteger" => (None, Some("0")),
                        "negativeInteger" => (None, Some("-1")),
                        _ => (None, None),
                    };
                    if min
                        .map(|b| n.checked_cmp(&ExactNumber::parse(b)?))
                        .transpose()?
                        .is_some_and(|o| o == Ordering::Less)
                        || max
                            .map(|b| n.checked_cmp(&ExactNumber::parse(b)?))
                            .transpose()?
                            .is_some_and(|o| o == Ordering::Greater)
                    {
                        return Err(Error::invalid("integer datatype range"));
                    }
                }
                "decimal" => {
                    value.as_number()?;
                }
                "float" | "double" => {
                    value.closed(&["format", "bits"], &[])?;
                    let (format, len) = if local == "float" {
                        ("binary32", 8)
                    } else {
                        ("binary64", 16)
                    };
                    let bits = value.field("bits")?.as_str()?;
                    if value.field("format")?.as_str() != Ok(format)
                        || bits.len() != len
                        || !bits
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    {
                        return Err(Error::invalid("float bits spelling"));
                    }
                    let bits =
                        u64::from_str_radix(bits, 16).map_err(|_| Error::invalid("float bits"))?;
                    let nonfinite = if len == 8 {
                        (bits >> 23) & 255 == 255
                    } else {
                        (bits >> 52) & 2047 == 2047
                    };
                    if nonfinite {
                        return Err(Error::invalid("nonfinite float"));
                    }
                }
                "dateTime" => {
                    Timestamp::parse(value.as_str()?)?;
                }
                "date" => {
                    validate_xsd_date(value.as_str()?)?;
                }
                _ => {
                    value.as_str()?;
                }
            }
        } else {
            value.as_str()?;
        }
        Ok(Self {
            datatype,
            value,
            language,
        })
    }
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(&["kind", "datatype", "value", "language"], &[])?;
        if v.field("kind")?.as_str()? != "literal" {
            return Err(Error::invalid("literal tag"));
        }
        Self::new(
            Iri::new(v.field("datatype")?.as_str()?)?,
            v.field("value")?.clone(),
            nullable_string(v.field("language")?)?,
        )
    }
    pub fn projection(&self) -> V {
        obj([
            ("kind", V::string("literal")),
            ("datatype", V::string(self.datatype.as_str())),
            ("value", self.value.clone()),
            (
                "language",
                self.language.as_ref().map(V::string).unwrap_or(V::Null),
            ),
        ])
    }
    pub fn datatype(&self) -> &Iri {
        &self.datatype
    }
    pub fn value(&self) -> &V {
        &self.value
    }
    pub fn language(&self) -> Option<&str> {
        self.language.as_deref()
    }
    pub fn exact_numeric(&self) -> Result<ExactNumber> {
        if let V::Number(n) = &self.value {
            return Ok(n.clone());
        }
        if matches!(
            self.datatype.as_str().strip_prefix(XSD),
            Some("float" | "double")
        ) {
            let bits = u64::from_str_radix(self.value.field("bits")?.as_str()?, 16)
                .map_err(|_| Error::invalid("float bits"))?;
            if self.datatype.as_str().ends_with("#float") {
                ExactNumber::from_binary32(bits as u32)
            } else {
                ExactNumber::from_binary64(bits)
            }
        } else {
            Err(Error::invalid("not numeric"))
        }
    }
}
fn validate_xsd_date(value: &str) -> Result<()> {
    use chrono::NaiveDate;

    let (date, timezone) = if let Some(date) = value.strip_suffix('Z') {
        (date, Some("Z"))
    } else if value.len() > 10 {
        let (date, timezone) = value.split_at(10);
        (date, Some(timezone))
    } else {
        (value, None)
    };
    if date.len() != 10
        || date.as_bytes()[4] != b'-'
        || date.as_bytes()[7] != b'-'
        || !date
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
        || NaiveDate::parse_from_str(date, "%Y-%m-%d").is_err()
    {
        return Err(Error::invalid("xsd:date lexical form"));
    }
    if let Some(timezone) = timezone {
        if timezone != "Z" {
            let bytes = timezone.as_bytes();
            if bytes.len() != 6
                || !matches!(bytes[0], b'+' | b'-')
                || bytes[3] != b':'
                || !bytes[1..3].iter().all(u8::is_ascii_digit)
                || !bytes[4..6].iter().all(u8::is_ascii_digit)
            {
                return Err(Error::invalid("xsd:date timezone"));
            }
            let hour = (bytes[1] - b'0') * 10 + (bytes[2] - b'0');
            let minute = (bytes[4] - b'0') * 10 + (bytes[5] - b'0');
            if hour > 14 || minute > 59 || (hour == 14 && minute != 0) {
                return Err(Error::invalid("xsd:date timezone"));
            }
        }
    }
    Ok(())
}

pub(crate) fn nullable_string(v: &V) -> Result<Option<String>> {
    if *v == V::Null {
        Ok(None)
    } else {
        Ok(Some(v.as_str()?.to_owned()))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimObject {
    Entity(EntityId),
    Literal(TypedLiteral),
}
impl ClaimObject {
    pub fn from_value(v: &V) -> Result<Self> {
        match v {
            V::String(s) => Ok(Self::Entity(EntityId::new(s)?)),
            _ => Ok(Self::Literal(TypedLiteral::from_value(v)?)),
        }
    }
    pub fn projection(&self) -> V {
        match self {
            Self::Entity(e) => V::string(e.as_str()),
            Self::Literal(l) => l.projection(),
        }
    }
    pub fn endpoint(&self) -> V {
        match self {
            Self::Entity(e) => obj([("kind", V::string("iri")), ("value", V::string(e.as_str()))]),
            Self::Literal(l) => l.projection(),
        }
    }
    pub fn from_endpoint(v: &V) -> Result<Self> {
        match v.field("kind")?.as_str()? {
            "iri" => {
                v.closed(&["kind", "value"], &[])?;
                Ok(Self::Entity(EntityId::new(v.field("value")?.as_str()?)?))
            }
            "literal" => Ok(Self::Literal(TypedLiteral::from_value(v)?)),
            _ => Err(Error::invalid("endpoint kind")),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Confidence(ExactNumber);
impl Confidence {
    pub fn new(n: ExactNumber) -> Result<Self> {
        if n.is_negative() || n.checked_cmp(&ExactNumber::from_u64(1))? == Ordering::Greater {
            return Err(Error::invalid("confidence outside [0,1]"));
        }
        Ok(Self(n))
    }
    pub fn number(&self) -> &ExactNumber {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Grounding {
    ClaimOnly,
    SourceLineageAvailable,
    SourceSpansAvailable,
}
impl Grounding {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "claim_only" => Ok(Self::ClaimOnly),
            "source_lineage_available" => Ok(Self::SourceLineageAvailable),
            "source_spans_available" => Ok(Self::SourceSpansAvailable),
            _ => Err(Error::invalid("grounding_level")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaimOnly => "claim_only",
            Self::SourceLineageAvailable => "source_lineage_available",
            Self::SourceSpansAvailable => "source_spans_available",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateClaim {
    id: ClaimId,
    subject: EntityId,
    relation: Iri,
    object: ClaimObject,
    relation_type: Iri,
    subject_type: Iri,
    object_type: Iri,
    claim_type: Iri,
    confidence: Confidence,
    grounding: Grounding,
    lineage: Lineage,
    ext: V,
    valid_time: Option<Timestamp>,
    source_observed_at: Option<Timestamp>,
}
impl CandidateClaim {
    /// Strict candidate wire. There is no transaction_time/lifecycle/depth input.
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(
            &[
                "claim_id",
                "subject_id",
                "relation",
                "object_id",
                "relation_type",
                "subject_type",
                "object_type",
                "claim_type",
                "confidence",
                "grounding_level",
            ],
            &["lineage", "ext", "valid_time", "source_observed_at"],
        )?;
        let o = v.as_object()?;
        let grounding = Grounding::parse(v.field("grounding_level")?.as_str()?)?;
        let lineage = match o.get("lineage") {
            Some(v) => Lineage::from_value(v)?,
            None => Lineage::empty(),
        };
        if grounding != Grounding::ClaimOnly && lineage.sources().is_empty() {
            return Err(Error::invalid("grounding requires sources"));
        }
        if grounding == Grounding::SourceSpansAvailable
            && lineage.sources().iter().any(|s| !s.has_span())
        {
            return Err(Error::invalid("grounding requires exact spans"));
        }
        let ext = o.get("ext").cloned().unwrap_or_else(|| obj([]));
        for k in ext.as_object()?.keys() {
            if k == "ctxql.core.temporal/v1"
                || [
                    "claim_id",
                    "subject_id",
                    "object_id",
                    "relation",
                    "relation_type",
                    "subject_type",
                    "object_type",
                    "claim_type",
                    "confidence",
                    "grounding_level",
                    "lineage",
                    "transaction_time",
                    "lifecycle_state",
                    "depth",
                    "ext",
                ]
                .contains(&k.as_str())
            {
                return Err(Error::invalid("reserved extension key"));
            }
        }
        let time = |key| {
            o.get(key)
                .map(|v| Timestamp::parse(v.as_str()?))
                .transpose()
        };
        let claim = Self {
            id: ClaimId::new(v.field("claim_id")?.as_str()?)?,
            subject: EntityId::new(v.field("subject_id")?.as_str()?)?,
            relation: Iri::new(v.field("relation")?.as_str()?)?,
            object: ClaimObject::from_value(v.field("object_id")?)?,
            relation_type: Iri::new(v.field("relation_type")?.as_str()?)?,
            subject_type: Iri::new(v.field("subject_type")?.as_str()?)?,
            object_type: Iri::new(v.field("object_type")?.as_str()?)?,
            claim_type: Iri::new(v.field("claim_type")?.as_str()?)?,
            confidence: Confidence::new(v.field("confidence")?.as_number()?.clone())?,
            grounding,
            lineage,
            ext,
            valid_time: time("valid_time")?,
            source_observed_at: time("source_observed_at")?,
        };
        if let Some(metadata) = claim.classification_metadata()? {
            metadata.validate_claim(&claim)?;
        }
        Ok(claim)
    }
    pub fn id(&self) -> &ClaimId {
        &self.id
    }
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }
    pub fn object(&self) -> &ClaimObject {
        &self.object
    }
    pub fn relation(&self) -> &Iri {
        &self.relation
    }
    pub fn is_lifecycle_assertion(&self) -> bool {
        matches!(
            self.relation.as_str(),
            "ctxql:superseded_by" | "ctxql:contradicted_by" | "ctxql:retracted_by"
        )
    }
    pub fn lineage(&self) -> &Lineage {
        &self.lineage
    }
    pub fn confidence(&self) -> &Confidence {
        &self.confidence
    }
    pub fn grounding(&self) -> Grounding {
        self.grounding
    }
    pub fn relation_type(&self) -> &Iri {
        &self.relation_type
    }
    pub fn subject_type(&self) -> &Iri {
        &self.subject_type
    }
    pub fn object_type(&self) -> &Iri {
        &self.object_type
    }
    pub fn claim_type(&self) -> &Iri {
        &self.claim_type
    }
    pub fn ext(&self) -> &V {
        &self.ext
    }
    /// Parsed acquisition-v2 classification metadata, when this is an
    /// acquisition-v2 claim. The enclosing extension is validated at input.
    pub fn classification_metadata(
        &self,
    ) -> Result<Option<crate::classification::ClassificationMetadata>> {
        self.ext
            .as_object()?
            .get(crate::classification::EXTENSION_KEY)
            .map(crate::classification::ClassificationMetadata::from_value)
            .transpose()
    }
    pub fn valid_time(&self) -> Option<Timestamp> {
        self.valid_time
    }
    pub fn source_observed_at(&self) -> Option<Timestamp> {
        self.source_observed_at
    }
    pub fn projection(&self) -> V {
        let mut v = obj([
            ("claim_id", V::string(self.id.as_str())),
            ("subject_id", V::string(self.subject.as_str())),
            ("relation", V::string(self.relation.as_str())),
            ("object_id", self.object.projection()),
            ("relation_type", V::string(self.relation_type.as_str())),
            ("subject_type", V::string(self.subject_type.as_str())),
            ("object_type", V::string(self.object_type.as_str())),
            ("claim_type", V::string(self.claim_type.as_str())),
            ("confidence", V::Number(self.confidence.0.clone())),
            ("grounding_level", V::string(self.grounding.as_str())),
            ("lineage", self.lineage.projection()),
            ("ext", self.ext.clone()),
        ]);
        if let V::Object(o) = &mut v {
            for (k, t) in [
                ("valid_time", self.valid_time),
                ("source_observed_at", self.source_observed_at),
            ] {
                if let Some(t) = t {
                    o.insert(k.into(), V::string(t.canonical()));
                }
            }
        }
        v
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedClaim {
    candidate: CandidateClaim,
    transaction_time: Timestamp,
}
impl AdmittedClaim {
    /// TRUSTED backend construction only: this factory is not proof of admission or permission.
    pub fn assign(candidate: CandidateClaim, transaction_time: Timestamp) -> Self {
        Self {
            candidate,
            transaction_time,
        }
    }
    pub fn candidate(&self) -> &CandidateClaim {
        &self.candidate
    }
    pub fn id(&self) -> &ClaimId {
        self.candidate.id()
    }
    pub fn transaction_time(&self) -> Timestamp {
        self.transaction_time
    }
    pub fn response(&self, state: LifecycleState) -> V {
        let V::Object(mut meta) = self.candidate.projection() else {
            unreachable!()
        };
        let mut temporal = std::collections::BTreeMap::new();
        for k in ["valid_time", "source_observed_at"] {
            if let Some(v) = meta.remove(k) {
                temporal.insert(k.into(), v);
            }
        }
        if !temporal.is_empty() {
            if let Some(V::Object(ext)) = meta.get_mut("ext") {
                ext.insert("ctxql.core.temporal/v1".into(), V::Object(temporal));
            }
        }
        meta.insert(
            "transaction_time".into(),
            V::string(self.transaction_time.canonical()),
        );
        meta.insert("lifecycle_state".into(), V::string(state.as_str()));
        obj([("meta", V::Object(meta))])
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    Active,
    Contradicted,
    Superseded,
    Retracted,
}
impl LifecycleState {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "active" => Ok(Self::Active),
            "contradicted" => Ok(Self::Contradicted),
            "superseded" => Ok(Self::Superseded),
            "retracted" => Ok(Self::Retracted),
            _ => Err(Error::invalid("lifecycle state")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Contradicted => "contradicted",
            Self::Superseded => "superseded",
            Self::Retracted => "retracted",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAssertion {
    claim: Box<CandidateClaim>,
    target: ClaimId,
    reference: LifecycleReference,
}
/// The object of a lifecycle claim; event identity is distinct from assertion identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleReference {
    Claim(ClaimId),
    Event(ResourceId),
}
impl LifecycleAssertion {
    pub fn new(claim: CandidateClaim) -> Result<Self> {
        let target = ClaimId::new(claim.subject().as_str())?;
        let ClaimObject::Entity(object) = claim.object() else {
            return Err(Error::invalid("lifecycle object must be a reference"));
        };
        if claim.id() == &target
            || object.as_str() == target.as_str()
            || object.as_str() == claim.id().as_str()
        {
            return Err(Error::invalid("lifecycle self reference"));
        }
        let reference = match claim.relation().as_str() {
            "ctxql:superseded_by" | "ctxql:contradicted_by" => {
                LifecycleReference::Claim(ClaimId::new(object.as_str())?)
            }
            "ctxql:retracted_by" => LifecycleReference::Event(ResourceId::new(object.as_str())?),
            _ => return Err(Error::invalid("lifecycle relation")),
        };
        Ok(Self {
            claim: Box::new(claim),
            target,
            reference,
        })
    }
    pub fn from_value(value: &V) -> Result<Self> {
        Self::new(CandidateClaim::from_value(value)?)
    }
    pub fn candidate(&self) -> &CandidateClaim {
        &self.claim
    }
    pub fn id(&self) -> &ClaimId {
        self.claim.id()
    }
    pub fn target(&self) -> &ClaimId {
        &self.target
    }
    pub fn reference(&self) -> &LifecycleReference {
        &self.reference
    }
    /// Referenced claim for supersession or contradiction, never an event.
    pub fn referenced_claim(&self) -> Option<&ClaimId> {
        match &self.reference {
            LifecycleReference::Claim(id) => Some(id),
            _ => None,
        }
    }
    pub fn event(&self) -> Option<&ResourceId> {
        match &self.reference {
            LifecycleReference::Event(id) => Some(id),
            _ => None,
        }
    }
    pub fn projection(&self) -> V {
        self.claim.projection()
    }
}

#[cfg(test)]
mod typed_literal_tests {
    use super::*;

    fn date(value: &str) -> Result<TypedLiteral> {
        TypedLiteral::new(
            Iri::new("http://www.w3.org/2001/XMLSchema#date")?,
            V::string(value),
            None,
        )
    }

    #[test]
    fn xsd_date_accepts_valid_calendar_and_timezone_forms() {
        assert!(date("2024-02-29").is_ok());
        assert!(date("2024-02-29Z").is_ok());
        assert!(date("2024-02-29+14:00").is_ok());
        assert!(date("2023-02-29").is_err());
        assert!(date("2024-02-29+14:01").is_err());
        assert!(date("2024-2-29").is_err());
    }
}
