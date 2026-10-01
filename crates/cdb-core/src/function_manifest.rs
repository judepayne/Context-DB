//! Closed, portable external-function manifest validation.
//! The exact published bytes remain the identity; parsed values never replace them.
use crate::artifact::{ArtifactRef, PublishedArtifact};
use crate::id::{ContentHash, Iri, ResourceId, VersionId};
use crate::{CanonicalValue as V, Error, Limits, Result};
use std::collections::{BTreeMap, BTreeSet};

pub const SCHEMA: &str = "ctxql-external-function/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Batching {
    None,
    Independent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueSchema {
    Null,
    Boolean,
    Number,
    String,
    Array {
        items: Box<ValueSchema>,
        max_items: usize,
    },
    Object {
        properties: BTreeMap<String, ValueSchema>,
        required: BTreeSet<String>,
    },
}
impl ValueSchema {
    fn parse(v: &V, depth: usize) -> Result<Self> {
        if depth > 32 {
            return Err(Error::limit());
        }
        let kind = v.field("type")?.as_str()?;
        match kind {
            "null" | "boolean" | "number" | "string" => {
                v.closed(&["type"], &[])?;
                Ok(match kind {
                    "null" => Self::Null,
                    "boolean" => Self::Boolean,
                    "number" => Self::Number,
                    _ => Self::String,
                })
            }
            "array" => {
                v.closed(&["type", "items", "max_items"], &[])?;
                let n = usize::try_from(v.field("max_items")?.as_number()?.to_u64()?)
                    .map_err(|_| Error::limit())?;
                if n == 0 {
                    return Err(Error::invalid("manifest array max_items must be positive"));
                }
                Ok(Self::Array {
                    items: Box::new(Self::parse(v.field("items")?, depth + 1)?),
                    max_items: n,
                })
            }
            "object" => {
                v.closed(
                    &["type", "properties", "required", "additional_properties"],
                    &[],
                )?;
                if v.field("additional_properties")?.as_bool()? {
                    return Err(Error::invalid("manifest schemas must be closed"));
                }
                let mut properties = BTreeMap::new();
                for (name, schema) in v.field("properties")?.as_object()? {
                    if name.is_empty() {
                        return Err(Error::invalid("empty schema property"));
                    }
                    properties.insert(name.clone(), Self::parse(schema, depth + 1)?);
                }
                let mut required = BTreeSet::new();
                for name in v.field("required")?.as_array()? {
                    let name = name.as_str()?.to_owned();
                    if !properties.contains_key(&name) || !required.insert(name) {
                        return Err(Error::invalid("invalid required schema property"));
                    }
                }
                Ok(Self::Object {
                    properties,
                    required,
                })
            }
            _ => Err(Error::invalid("unknown manifest value type")),
        }
    }
    pub fn validate(&self, value: &V) -> Result<()> {
        match (self, value) {
            (Self::Null, V::Null)
            | (Self::Boolean, V::Bool(_))
            | (Self::Number, V::Number(_))
            | (Self::String, V::String(_)) => Ok(()),
            (Self::Array { items, max_items }, V::Array(values)) => {
                if values.len() > *max_items {
                    return Err(Error::limit());
                }
                values.iter().try_for_each(|v| items.validate(v))
            }
            (
                Self::Object {
                    properties,
                    required,
                },
                V::Object(values),
            ) => {
                if values.keys().any(|k| !properties.contains_key(k))
                    || required.iter().any(|k| !values.contains_key(k))
                {
                    return Err(Error::invalid("value does not match closed object schema"));
                }
                values
                    .iter()
                    .try_for_each(|(k, v)| properties[k].validate(v))
            }
            _ => Err(Error::invalid("value does not match manifest schema")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImplementationIdentity {
    pub implementation: Iri,
    pub version: VersionId,
    pub build: ContentHash,
    pub model: Option<ResourceId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalFunctionManifest {
    artifact: ArtifactRef,
    exact_bytes: Vec<u8>,
    name: ResourceId,
    version: VersionId,
    implementation: ImplementationIdentity,
    input: ValueSchema,
    output: ValueSchema,
    semantic_parameters: V,
    capabilities: BTreeSet<ResourceId>,
    deterministic: bool,
    order_independent: bool,
    retry_safe: bool,
    batching: Batching,
}
impl ExternalFunctionManifest {
    pub fn from_published(artifact: &PublishedArtifact, limits: Limits) -> Result<Self> {
        let root = V::parse(artifact.content(), limits)?;
        root.closed(
            &[
                "schema",
                "name",
                "version",
                "implementation",
                "input_schema",
                "output_schema",
                "semantic_parameters",
                "capabilities",
                "declarations",
            ],
            &[],
        )?;
        if root.field("schema")?.as_str()? != SCHEMA {
            return Err(Error::invalid("function manifest schema"));
        }
        let name = ResourceId::new(root.field("name")?.as_str()?)?;
        let version = VersionId::new(root.field("version")?.as_str()?)?;
        if &version != artifact.reference().version() {
            return Err(Error::invalid("manifest version binding mismatch"));
        }
        let implementation_value = root.field("implementation")?;
        implementation_value.closed(&["implementation", "version", "build", "model"], &[])?;
        let model = match implementation_value.field("model")? {
            V::Null => None,
            v => Some(ResourceId::new(v.as_str()?)?),
        };
        let implementation = ImplementationIdentity {
            implementation: Iri::new(implementation_value.field("implementation")?.as_str()?)?,
            version: VersionId::new(implementation_value.field("version")?.as_str()?)?,
            build: ContentHash::parse(implementation_value.field("build")?.as_str()?)?,
            model,
        };
        let semantic_parameters = root.field("semantic_parameters")?.clone();
        if !matches!(semantic_parameters, V::Object(_)) {
            return Err(Error::invalid("semantic_parameters must be object"));
        }
        semantic_parameters.canonical_bytes(limits)?;
        let mut capabilities = BTreeSet::new();
        for value in root.field("capabilities")?.as_array()? {
            if !capabilities.insert(ResourceId::new(value.as_str()?)?) {
                return Err(Error::invalid("duplicate capability"));
            }
        }
        let declarations = root.field("declarations")?;
        declarations.closed(
            &[
                "deterministic",
                "order_independent",
                "retry_safe",
                "batching",
            ],
            &[],
        )?;
        let batching = match declarations.field("batching")?.as_str()? {
            "none" => Batching::None,
            "independent" => Batching::Independent,
            _ => return Err(Error::invalid("unknown batching declaration")),
        };
        Ok(Self {
            artifact: artifact.reference().clone(),
            exact_bytes: artifact.content().to_vec(),
            name,
            version,
            implementation,
            input: ValueSchema::parse(root.field("input_schema")?, 0)?,
            output: ValueSchema::parse(root.field("output_schema")?, 0)?,
            semantic_parameters,
            capabilities,
            deterministic: declarations.field("deterministic")?.as_bool()?,
            order_independent: declarations.field("order_independent")?.as_bool()?,
            retry_safe: declarations.field("retry_safe")?.as_bool()?,
            batching,
        })
    }
    pub fn artifact(&self) -> &ArtifactRef {
        &self.artifact
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
    pub fn name(&self) -> &ResourceId {
        &self.name
    }
    pub fn version(&self) -> &VersionId {
        &self.version
    }
    pub fn implementation(&self) -> &ImplementationIdentity {
        &self.implementation
    }
    pub fn input_schema(&self) -> &ValueSchema {
        &self.input
    }
    pub fn output_schema(&self) -> &ValueSchema {
        &self.output
    }
    pub fn semantic_parameters(&self) -> &V {
        &self.semantic_parameters
    }
    pub fn capabilities(&self) -> &BTreeSet<ResourceId> {
        &self.capabilities
    }
    pub fn deterministic(&self) -> bool {
        self.deterministic
    }
    pub fn order_independent(&self) -> bool {
        self.order_independent
    }
    pub fn retry_safe(&self) -> bool {
        self.retry_safe
    }
    pub fn batching(&self) -> Batching {
        self.batching
    }
}
