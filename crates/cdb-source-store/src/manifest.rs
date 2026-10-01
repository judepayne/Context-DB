use cdb_core::{id::ContentHash, CanonicalValue as V, Error, ExactNumber, Limits, Result};
const MAX_LABEL: usize = 4_096;
const MAX_ARGV: usize = 128;

fn object<const N: usize>(fields: [(&str, V); N]) -> V {
    V::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

fn number(value: u64) -> V {
    V::Number(ExactNumber::parse(&value.to_string()).expect("u64 is an exact JSON number"))
}

fn bounded_string(value: &str, name: &'static str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_LABEL || value.chars().any(char::is_control) {
        return Err(Error::invalid(name));
    }
    Ok(())
}

fn canonical(value: &V) -> Result<Vec<u8>> {
    value.canonical_bytes(Limits::default())
}

fn parse_canonical(bytes: &[u8]) -> Result<V> {
    let value = V::parse(bytes, Limits::default())?;
    if canonical(&value)? != bytes {
        return Err(Error::invalid("non-canonical representation manifest"));
    }
    Ok(value)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Normalization {
    None,
    Declared(String),
}

impl Normalization {
    fn value(&self) -> V {
        match self {
            Self::None => object([("kind", V::string("none"))]),
            Self::Declared(value) => object([
                ("declaration", V::string(value)),
                ("kind", V::string("declared")),
            ]),
        }
    }

    fn from_value(value: &V) -> Result<Self> {
        let kind = value.field("kind")?.as_str()?;
        match kind {
            "none" => {
                value.closed(&["kind"], &[])?;
                Ok(Self::None)
            }
            "declared" => {
                value.closed(&["declaration", "kind"], &[])?;
                let declaration = value.field("declaration")?.as_str()?;
                bounded_string(declaration, "normalization declaration")?;
                Ok(Self::Declared(declaration.to_owned()))
            }
            _ => Err(Error::invalid("normalization kind")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConverterManifest {
    executable: ContentHash,
    version_probe: String,
    argv: Vec<String>,
    timeout_ms: u64,
    output_limit: u64,
    normalization: Normalization,
}

impl ConverterManifest {
    pub fn new(
        executable: ContentHash,
        version_probe: impl Into<String>,
        argv: Vec<String>,
        timeout_ms: u64,
        output_limit: u64,
        normalization: Normalization,
    ) -> Result<Self> {
        let version_probe = version_probe.into();
        bounded_string(&version_probe, "converter version probe")?;
        if argv.len() > MAX_ARGV || timeout_ms == 0 || output_limit == 0 {
            return Err(Error::invalid("converter manifest limits"));
        }
        for argument in &argv {
            bounded_string(argument, "converter argument")?;
        }
        if let Normalization::Declared(value) = &normalization {
            bounded_string(value, "normalization declaration")?;
        }
        Ok(Self {
            executable,
            version_probe,
            argv,
            timeout_ms,
            output_limit,
            normalization,
        })
    }

    fn value(&self) -> V {
        object([
            ("argv", V::Array(self.argv.iter().map(V::string).collect())),
            ("encoding", V::string("utf-8")),
            ("executable", V::string(self.executable.as_str())),
            ("normalization", self.normalization.value()),
            ("output_limit", number(self.output_limit)),
            ("schema", V::string("ctxql-converter-manifest/v1")),
            ("timeout_ms", number(self.timeout_ms)),
            ("version_probe", V::string(&self.version_probe)),
        ])
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical(&self.value())
    }

    pub fn id(&self) -> Result<ContentHash> {
        Ok(ContentHash::of_bytes(&self.canonical_bytes()?))
    }

    pub fn executable(&self) -> &ContentHash {
        &self.executable
    }

    pub fn normalization(&self) -> &Normalization {
        &self.normalization
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let value = parse_canonical(bytes)?;
        value.closed(
            &[
                "argv",
                "encoding",
                "executable",
                "normalization",
                "output_limit",
                "schema",
                "timeout_ms",
                "version_probe",
            ],
            &[],
        )?;
        if value.field("schema")?.as_str()? != "ctxql-converter-manifest/v1"
            || value.field("encoding")?.as_str()? != "utf-8"
        {
            return Err(Error::invalid("converter manifest schema"));
        }
        let argv = value
            .field("argv")?
            .as_array()?
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Result<Vec<_>>>()?;
        Self::new(
            ContentHash::parse(value.field("executable")?.as_str()?)?,
            value.field("version_probe")?.as_str()?,
            argv,
            value.field("timeout_ms")?.u64()?,
            value.field("output_limit")?.u64()?,
            Normalization::from_value(value.field("normalization")?)?,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalRepresentationManifest {
    object: ContentHash,
    media_type: String,
    acquisition_metadata_root: ContentHash,
}

impl OriginalRepresentationManifest {
    pub fn new(
        object: ContentHash,
        media_type: impl Into<String>,
        acquisition_metadata_root: ContentHash,
    ) -> Result<Self> {
        let media_type = media_type.into();
        if media_type.len() > 255
            || !media_type.contains('/')
            || media_type.chars().any(char::is_whitespace)
        {
            return Err(Error::invalid("media type"));
        }
        Ok(Self {
            object,
            media_type,
            acquisition_metadata_root,
        })
    }

    fn value(&self) -> V {
        object([
            (
                "acquisition_metadata_root",
                V::string(self.acquisition_metadata_root.as_str()),
            ),
            ("media_type", V::string(&self.media_type)),
            ("object", V::string(self.object.as_str())),
            ("schema", V::string("ctxql-original-representation/v1")),
        ])
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical(&self.value())
    }

    pub fn id(&self) -> Result<ContentHash> {
        Ok(ContentHash::of_bytes(&self.canonical_bytes()?))
    }

    pub fn object(&self) -> &ContentHash {
        &self.object
    }

    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let value = parse_canonical(bytes)?;
        value.closed(
            &[
                "acquisition_metadata_root",
                "media_type",
                "object",
                "schema",
            ],
            &[],
        )?;
        if value.field("schema")?.as_str()? != "ctxql-original-representation/v1" {
            return Err(Error::invalid("original representation schema"));
        }
        Self::new(
            ContentHash::parse(value.field("object")?.as_str()?)?,
            value.field("media_type")?.as_str()?,
            ContentHash::parse(value.field("acquisition_metadata_root")?.as_str()?)?,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextRepresentationManifest {
    object: ContentHash,
    original_manifest: ContentHash,
    converter_manifest: ContentHash,
    version: ContentHash,
}

impl TextRepresentationManifest {
    fn version_value(object_hash: &ContentHash, converter_manifest: &ContentHash) -> V {
        object([
            ("converter_manifest", V::string(converter_manifest.as_str())),
            ("object", V::string(object_hash.as_str())),
            ("schema", V::string("ctxql-text-version/v1")),
        ])
    }

    pub fn new(
        object_hash: ContentHash,
        original_manifest: ContentHash,
        converter_manifest: ContentHash,
    ) -> Result<Self> {
        let version_value = Self::version_value(&object_hash, &converter_manifest);
        let version = ContentHash::of_bytes(&canonical(&version_value)?);
        Ok(Self {
            object: object_hash,
            original_manifest,
            converter_manifest,
            version,
        })
    }

    fn value(&self) -> V {
        object([
            (
                "converter_manifest",
                V::string(self.converter_manifest.as_str()),
            ),
            ("object", V::string(self.object.as_str())),
            (
                "original_manifest",
                V::string(self.original_manifest.as_str()),
            ),
            ("schema", V::string("ctxql-text-representation/v1")),
            ("version", V::string(self.version.as_str())),
        ])
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical(&self.value())
    }

    pub fn version_bytes(&self) -> Result<Vec<u8>> {
        canonical(&Self::version_value(&self.object, &self.converter_manifest))
    }

    pub fn id(&self) -> Result<ContentHash> {
        Ok(ContentHash::of_bytes(&self.canonical_bytes()?))
    }

    pub fn object(&self) -> &ContentHash {
        &self.object
    }

    pub fn original_manifest(&self) -> &ContentHash {
        &self.original_manifest
    }

    pub fn converter_manifest(&self) -> &ContentHash {
        &self.converter_manifest
    }

    pub fn version(&self) -> &ContentHash {
        &self.version
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let value = parse_canonical(bytes)?;
        value.closed(
            &[
                "converter_manifest",
                "object",
                "original_manifest",
                "schema",
                "version",
            ],
            &[],
        )?;
        if value.field("schema")?.as_str()? != "ctxql-text-representation/v1" {
            return Err(Error::invalid("text representation schema"));
        }
        let manifest = Self::new(
            ContentHash::parse(value.field("object")?.as_str()?)?,
            ContentHash::parse(value.field("original_manifest")?.as_str()?)?,
            ContentHash::parse(value.field("converter_manifest")?.as_str()?)?,
        )?;
        if manifest.version.as_str() != value.field("version")?.as_str()? {
            return Err(Error::invalid("text representation version"));
        }
        Ok(manifest)
    }
}
