//! Versioned immutable provenance for a stored record image; not an authorization credential.
use crate::{
    admission::{DependencyRecord, ExportRecord, Fact, FactTerm, ResourceKind},
    claim::TypedLiteral,
    id::{ContentHash, Iri, ResourceId},
    record_codec::encode_record,
    CanonicalValue as V, Error, Limits, Result, Timestamp,
};

pub const INTERNAL_PREFIX: &str = "https://ctxql.example/storage/v1/";
pub const ORIGIN_PREDICATE: &str = "https://ctxql.example/storage/v1/origin";
const SCHEMA: &str = "ctxql-record-origin/v1";
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordOrigin {
    key: String,
    image: ContentHash,
    sequence: u64,
    time: Timestamp,
    removed: bool,
}
impl RecordOrigin {
    pub fn new(
        record: &ExportRecord,
        sequence: u64,
        time: Timestamp,
        removed: bool,
        limits: Limits,
    ) -> Result<Self> {
        if sequence == 0 {
            return Err(Error::invalid("origin sequence"));
        }
        Ok(Self {
            key: record.identity_key(),
            image: ContentHash::of_bytes(&encode_record(record, limits)?),
            sequence,
            time,
            removed,
        })
    }
    pub fn key(&self) -> &str {
        &self.key
    }
    pub fn image(&self) -> &ContentHash {
        &self.image
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn time(&self) -> Timestamp {
        self.time
    }
    pub fn removed(&self) -> bool {
        self.removed
    }
    pub fn id(&self) -> Result<ResourceId> {
        ResourceId::new(format!(
            "{INTERNAL_PREFIX}origin/{}/{}/{}",
            self.sequence,
            if self.removed { "remove" } else { "put" },
            ContentHash::of_bytes(self.key.as_bytes()).as_str()
        ))
    }
    pub fn resource(&self, limits: Limits) -> Result<DependencyRecord> {
        let value = V::Object(
            [
                ("schema".into(), V::string(SCHEMA)),
                ("key".into(), V::string(&self.key)),
                ("image".into(), V::string(self.image.as_str())),
                ("sequence".into(), V::integer(self.sequence)),
                ("transaction_time".into(), V::string(self.time.canonical())),
                ("removed".into(), V::Bool(self.removed)),
            ]
            .into(),
        );
        let bytes = value.canonical_bytes(limits)?;
        DependencyRecord::new(
            "ctxql-resource/v1",
            self.id()?,
            ResourceKind::SourceDescriptor,
            vec![Fact::new(
                Iri::new(ORIGIN_PREDICATE)?,
                FactTerm::Literal(TypedLiteral::new(
                    Iri::new("http://www.w3.org/2001/XMLSchema#string")?,
                    V::string(
                        String::from_utf8(bytes).map_err(|_| Error::invalid("origin UTF-8"))?,
                    ),
                    None,
                )?),
            )],
        )
    }
    pub fn from_resource(record: &DependencyRecord, limits: Limits) -> Result<Option<Self>> {
        if !record
            .id()
            .as_str()
            .starts_with(&format!("{INTERNAL_PREFIX}origin/"))
        {
            return Ok(None);
        }
        if record.kind() != ResourceKind::SourceDescriptor
            || record.facts().len() != 1
            || record.facts()[0].predicate().as_str() != ORIGIN_PREDICATE
        {
            return Err(Error::invalid("origin descriptor"));
        }
        let FactTerm::Literal(literal) = record.facts()[0].term() else {
            return Err(Error::invalid("origin literal"));
        };
        let projection = literal.projection();
        if projection.field("datatype")?.as_str()? != "http://www.w3.org/2001/XMLSchema#string"
            || *projection.field("language")? != V::Null
        {
            return Err(Error::invalid("origin datatype"));
        }
        let value = V::parse(projection.field("value")?.as_str()?.as_bytes(), limits)?;
        value.closed(
            &[
                "schema",
                "key",
                "image",
                "sequence",
                "transaction_time",
                "removed",
            ],
            &[],
        )?;
        if value.field("schema")?.as_str()? != SCHEMA {
            return Err(Error::invalid("origin schema"));
        }
        let result = Self {
            key: value.field("key")?.as_str()?.into(),
            image: ContentHash::parse(value.field("image")?.as_str()?)?,
            sequence: value.field("sequence")?.u64()?,
            time: Timestamp::parse(value.field("transaction_time")?.as_str()?)?,
            removed: value.field("removed")?.as_bool()?,
        };
        if result.sequence == 0 || result.id()? != *record.id() {
            return Err(Error::invalid("origin identity"));
        }
        Ok(Some(result))
    }
    pub fn matches(&self, record: &ExportRecord, limits: Limits) -> Result<bool> {
        Ok(self.key == record.identity_key()
            && self.image == ContentHash::of_bytes(&encode_record(record, limits)?))
    }
}
