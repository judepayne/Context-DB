use crate::values::Value;
use cdb_core::{
    claim::{Grounding, LifecycleState},
    CanonicalValue as V, Error, Result, Timestamp,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldType {
    Dynamic,
    String,
    Identifier,
    Number,
    Timestamp,
    Grounding,
    Lifecycle,
    Object,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldRef {
    spelling: String,
    key: String,
    path: bool,
    kind: FieldType,
}
impl FieldRef {
    pub fn parse(s: &str) -> Result<Self> {
        cdb_core::id::ResourceId::new(s)?;
        let (path, s) = match s.strip_prefix("path.") {
            Some(s) => (true, s),
            None => (false, s),
        };
        let key = s
            .strip_prefix("meta:")
            .ok_or_else(|| Error::invalid("field reference"))?;
        let kind = match key {
            "claim_id" | "subject_id" => FieldType::String,
            "object_id" => FieldType::Dynamic,
            "relation" | "relation_type" | "subject_type" | "object_type" | "claim_type" => {
                FieldType::Identifier
            }
            "confidence" | "depth" => FieldType::Number,
            "transaction_time" => FieldType::Timestamp,
            "grounding_level" => FieldType::Grounding,
            "lifecycle_state" => FieldType::Lifecycle,
            "lineage" | "ext" => FieldType::Object,
            _ if key.starts_with("ext:")
                && key.len() > 4
                && !key[4..].chars().any(char::is_whitespace) =>
            {
                FieldType::Dynamic
            }
            _ => return Err(Error::invalid("unknown or malformed field")),
        };
        Ok(Self {
            spelling: format!("{}{}", if path { "path." } else { "" }, s),
            key: key.to_owned(),
            path,
            kind,
        })
    }
    pub fn spelling(&self) -> &str {
        &self.spelling
    }
    pub fn metadata_key(&self) -> &str {
        &self.key
    }
    /// Exact stored extension key, not a dot-separated object path.
    pub fn extension_key(&self) -> Option<&str> {
        self.key.strip_prefix("ext:")
    }
    pub fn is_path(&self) -> bool {
        self.path
    }
    pub fn field_type(&self) -> FieldType {
        self.kind
    }
    pub fn mapping_key(&self) -> String {
        format!("meta:{}", self.key)
    }
    /// Convert a looked-up metadata value using the field's declared type.
    /// Pass path lists with Missing entries directly as Value::List instead.
    pub fn value(&self, value: cdb_core::Lookup<'_>) -> Result<Value> {
        match value {
            cdb_core::Lookup::Missing => Ok(Value::Missing),
            cdb_core::Lookup::Present(v) => self.scalar_value(v),
        }
    }
    pub(crate) fn scalar_value(&self, v: &V) -> Result<Value> {
        if *v == V::Null {
            return Ok(Value::Null);
        }
        if matches!(
            self.kind,
            FieldType::Number | FieldType::String | FieldType::Timestamp
        ) && v.as_object().ok().and_then(|o| o.get("kind")) == Some(&V::string("literal"))
        {
            return Value::from_json(v);
        }
        Ok(match self.kind {
            FieldType::Timestamp => Value::Timestamp(Timestamp::parse(v.as_str()?)?),
            FieldType::Grounding => Value::Grounding(Grounding::parse(v.as_str()?)?),
            FieldType::Lifecycle => {
                LifecycleState::parse(v.as_str()?)?;
                Value::String(v.as_str()?.to_owned())
            }
            FieldType::Number => Value::Number(v.as_number()?.clone()),
            FieldType::String | FieldType::Identifier => Value::String(v.as_str()?.to_owned()),
            FieldType::Dynamic => Value::from_json(v)?,
            FieldType::Object => Value::Object(v.clone()),
        })
    }
}
