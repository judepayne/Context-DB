//! Explicit immutable artifacts. Query/profile bytes use the shared frontend; configs remain JSON.
use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    Error, ErrorKind, Limits, Result,
};
use std::{collections::BTreeMap, fs, io::Read, path::Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ArtifactKind {
    Query,
    Profile,
    Config,
}
impl ArtifactKind {
    fn directory(self) -> &'static str {
        match self {
            Self::Query => "queries",
            Self::Profile => "profiles",
            Self::Config => "configs",
        }
    }
}

/// Portable slash-separated logical name, never an OS path or an IRI.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ArtifactName(String);
impl ArtifactName {
    pub fn new(name: &str, max_bytes: usize) -> Result<Self> {
        if name.len() > max_bytes {
            return Err(Error::limit());
        }
        if name.is_empty()
            || name
                .chars()
                .any(|c| c.is_control() || matches!(c, '\\' | ':' | '%'))
            || name
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == ".." || p.ends_with(['.', ' ']))
        {
            return Err(Error::invalid("invalid artifact name"));
        }
        Ok(Self(name.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// All budgets are injected. Zero is a rejecting budget, not an unlimited default.
#[derive(Clone, Copy, Debug)]
pub struct CatalogOptions {
    pub limits: Limits,
    pub max_entries: usize,
    pub max_name_bytes: usize,
    /// Sum of exact content, names, and reference string bytes (not allocator overhead).
    pub max_retained_bytes: usize,
}

/// Construct once; entries can neither be replaced nor removed.
#[derive(Debug)]
pub struct Catalog {
    entries: BTreeMap<(ArtifactKind, ArtifactName), PublishedArtifact>,
    retained_bytes: usize,
}
impl Catalog {
    pub fn new(
        entries: impl IntoIterator<Item = (ArtifactKind, ArtifactName, PublishedArtifact)>,
        options: CatalogOptions,
    ) -> Result<Self> {
        let mut catalog = Self {
            entries: BTreeMap::new(),
            retained_bytes: 0,
        };
        // Bound submitted dependencies as well as retained entries, including retries.
        for (index, (kind, name, artifact)) in entries.into_iter().enumerate() {
            if index >= options.limits.work() {
                return Err(Error::limit());
            }
            if name.as_str().len() > options.max_name_bytes {
                return Err(Error::limit());
            }
            let key = (kind, name);
            if let Some(previous) = catalog.entries.get(&key) {
                if previous != &artifact {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "artifact name already pinned",
                    ));
                }
                continue;
            }
            if catalog.entries.len() >= options.max_entries {
                return Err(Error::limit());
            }
            let reference = artifact.reference();
            let retained = [
                artifact.content().len(),
                key.1.as_str().len(),
                reference.iri().as_str().len(),
                reference.version().as_str().len(),
                reference.hash().as_str().len(),
            ]
            .into_iter()
            .try_fold(catalog.retained_bytes, |n, size| n.checked_add(size))
            .ok_or_else(Error::limit)?;
            if retained > options.max_retained_bytes {
                return Err(Error::limit());
            }
            crate::frontend::parse_syntax(kind, artifact.content(), options.limits)?;
            catalog.entries.insert(key, artifact);
            catalog.retained_bytes = retained;
        }
        Ok(catalog)
    }

    /// Missing name and mismatched immutable reference are distinct failures.
    pub fn resolve(
        &self,
        kind: ArtifactKind,
        name: &ArtifactName,
        expected: &ArtifactRef,
    ) -> Result<&PublishedArtifact> {
        let artifact = self
            .entries
            .get(&(kind, name.clone()))
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "artifact absent"))?;
        if artifact.reference() != expected {
            return Err(Error::new(
                ErrorKind::Conflict,
                "artifact reference mismatch",
            ));
        }
        Ok(artifact)
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
}

fn io_error(error: std::io::Error) -> Error {
    let kind = if error.kind() == std::io::ErrorKind::NotFound {
        ErrorKind::NotFound
    } else {
        ErrorKind::Backend
    };
    Error::new(kind, "artifact filesystem read failed")
}

/// Read `root/{queries,profiles,configs}/name.json`, verify published bytes, then
/// validate with the shared frontend (configs remain strict JSON). Root must be caller-owned and stable during this
/// operation: portable std canonicalization is not an atomic sandbox against a
/// concurrent hostile filesystem mutator. Static symlink escapes are rejected.
pub fn read_json(
    root: &Path,
    kind: ArtifactKind,
    name: &ArtifactName,
    expected: &ArtifactRef,
    limits: Limits,
) -> Result<PublishedArtifact> {
    let root = fs::canonicalize(root).map_err(io_error)?;
    if !root.is_dir() {
        return Err(Error::invalid("artifact root is not a directory"));
    }
    let path = fs::canonicalize(
        root.join(kind.directory())
            .join(format!("{}.json", name.as_str())),
    )
    .map_err(io_error)?;
    if !path.starts_with(&root) {
        return Err(Error::invalid("artifact escapes explicit root"));
    }
    let mut file = fs::File::open(path).map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file() {
        return Err(Error::invalid("artifact is not a regular file"));
    }
    if u128::from(metadata.len()) > limits.input_bytes() as u128 {
        return Err(Error::limit());
    }
    // Fixed-size chunks also detect growth without ever retaining ceiling+1 bytes.
    let mut content = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let count = file.read(&mut chunk).map_err(io_error)?;
        if count == 0 {
            break;
        }
        if count > limits.input_bytes().saturating_sub(content.len()) {
            return Err(Error::limit());
        }
        content.extend_from_slice(&chunk[..count]);
    }
    let artifact = PublishedArtifact::new(expected.clone(), content, limits)?;
    crate::frontend::parse_syntax(kind, artifact.content(), limits)?;
    Ok(artifact)
}
