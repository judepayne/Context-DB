//! Canonical immutable source and extraction-text representation identities.
//! Filesystem paths, converter processes, and acquisition authority stay outside core.

use crate::id::{ContentHash, DocumentId, Iri, SourceId, VersionId};
use crate::{CanonicalValue as V, Error, Limits, Result};
use std::collections::BTreeMap;

fn obj(fields: impl IntoIterator<Item = (&'static str, V)>) -> V {
    V::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConverterIdentity {
    executable_hash: ContentHash,
    version: VersionId,
    arguments: Vec<String>,
    encoding: String,
    normalization: String,
    root: ContentHash,
}

impl ConverterIdentity {
    pub fn new(
        executable_hash: ContentHash,
        version: VersionId,
        arguments: Vec<String>,
        encoding: impl Into<String>,
        normalization: impl Into<String>,
        limits: Limits,
    ) -> Result<Self> {
        let encoding = encoding.into();
        let normalization = normalization.into();
        if encoding != "UTF-8"
            || normalization.is_empty()
            || normalization.len() > 256
            || normalization.chars().any(char::is_control)
            || arguments.len() > 64
            || arguments
                .iter()
                .any(|arg| arg.len() > 4096 || arg.chars().any(char::is_control))
        {
            return Err(Error::invalid("converter identity"));
        }
        let projection = obj([
            ("schema", V::string("ctxql-converter/v1")),
            ("executable_hash", V::string(executable_hash.as_str())),
            ("version", V::string(version.as_str())),
            (
                "arguments",
                V::Array(arguments.iter().map(V::string).collect()),
            ),
            ("encoding", V::string(&encoding)),
            ("normalization", V::string(&normalization)),
        ]);
        let root = ContentHash::of_bytes(&projection.canonical_bytes(limits)?);
        Ok(Self {
            executable_hash,
            version,
            arguments,
            encoding,
            normalization,
            root,
        })
    }

    pub fn identity(&self) -> &ContentHash {
        &self.root
    }

    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql-converter/v1")),
            ("executable_hash", V::string(self.executable_hash.as_str())),
            ("version", V::string(self.version.as_str())),
            (
                "arguments",
                V::Array(self.arguments.iter().map(V::string).collect()),
            ),
            ("encoding", V::string(&self.encoding)),
            ("normalization", V::string(&self.normalization)),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRepresentation {
    document_id: DocumentId,
    locator: Iri,
    original_source: SourceId,
    original_object: ContentHash,
    original_media_type: String,
    text_source: SourceId,
    text_object: ContentHash,
    converter: ConverterIdentity,
    acquisition_metadata_root: ContentHash,
    text_version: ContentHash,
}

impl SourceRepresentation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        document_id: DocumentId,
        locator: Iri,
        original_source: SourceId,
        original_object: ContentHash,
        original_media_type: impl Into<String>,
        text_source: SourceId,
        text_object: ContentHash,
        converter: ConverterIdentity,
        acquisition_metadata: BTreeMap<String, V>,
        limits: Limits,
    ) -> Result<Self> {
        let original_media_type = original_media_type.into();
        if original_media_type.is_empty()
            || original_media_type.len() > 256
            || original_media_type.chars().any(char::is_control)
        {
            return Err(Error::invalid("source media type"));
        }
        let acquisition_metadata_value = V::Object(acquisition_metadata);
        let acquisition_metadata_root =
            ContentHash::of_bytes(&acquisition_metadata_value.canonical_bytes(limits)?);
        let text_version_value = obj([
            ("schema", V::string("ctxql-text-version/v1")),
            ("text_object", V::string(text_object.as_str())),
            ("converter", V::string(converter.identity().as_str())),
        ]);
        let text_version = ContentHash::of_bytes(&text_version_value.canonical_bytes(limits)?);
        Ok(Self {
            document_id,
            locator,
            original_source,
            original_object,
            original_media_type,
            text_source,
            text_object,
            converter,
            acquisition_metadata_root,
            text_version,
        })
    }

    pub fn document_id(&self) -> &DocumentId {
        &self.document_id
    }
    pub fn locator(&self) -> &Iri {
        &self.locator
    }
    pub fn original_object(&self) -> &ContentHash {
        &self.original_object
    }
    pub fn text_object(&self) -> &ContentHash {
        &self.text_object
    }
    pub fn text_version(&self) -> &ContentHash {
        &self.text_version
    }
    pub fn converter(&self) -> &ConverterIdentity {
        &self.converter
    }

    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql-source-representation/v1")),
            ("document_id", V::string(self.document_id.as_str())),
            ("locator", V::string(self.locator.as_str())),
            ("original_source", V::string(self.original_source.as_str())),
            ("original_object", V::string(self.original_object.as_str())),
            ("original_media_type", V::string(&self.original_media_type)),
            ("text_source", V::string(self.text_source.as_str())),
            ("text_object", V::string(self.text_object.as_str())),
            ("text_version", V::string(self.text_version.as_str())),
            ("converter", self.converter.projection()),
            (
                "acquisition_metadata_root",
                V::string(self.acquisition_metadata_root.as_str()),
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> ContentHash {
        ContentHash::of_bytes(&[byte])
    }

    #[test]
    fn text_version_binds_converter_and_text_not_locator() {
        let converter = ConverterIdentity::new(
            hash(1),
            VersionId::new("plain/v1").unwrap(),
            vec![],
            "UTF-8",
            "none",
            Limits::default(),
        )
        .unwrap();
        let make = |locator: &str, text: ContentHash| {
            SourceRepresentation::new(
                DocumentId::new("doc").unwrap(),
                Iri::new(locator).unwrap(),
                SourceId::new("original").unwrap(),
                hash(2),
                "text/plain",
                SourceId::new("text").unwrap(),
                text,
                converter.clone(),
                BTreeMap::new(),
                Limits::default(),
            )
            .unwrap()
        };
        let first = make("file:///a", hash(3));
        let moved = make("file:///b", hash(3));
        let changed = make("file:///a", hash(4));
        assert_eq!(first.text_version(), moved.text_version());
        assert_ne!(first.text_version(), changed.text_version());
    }

    #[test]
    fn converter_rejects_implicit_normalization() {
        assert!(ConverterIdentity::new(
            hash(1),
            VersionId::new("v1").unwrap(),
            vec![],
            "UTF-8",
            "",
            Limits::default(),
        )
        .is_err());
    }
}
