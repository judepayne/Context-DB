//! Bounded acquisition of one foreground-ingest source target.

use crate::config::{AcquisitionConfig, AcquisitionUrlAdapterConfig};
use cdb_core::{Error, ErrorKind, Result};
use reqwest::{redirect::Policy, Url};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceTarget {
    LocalFile(PathBuf),
    HttpsUrl(String),
    LocalFolder(PathBuf),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaKind {
    Text,
    Markdown,
    Pdf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceLocator {
    Local(PathBuf),
    Https(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquiredDocument {
    pub locator: SourceLocator,
    pub bytes: Vec<u8>,
    pub media_kind: MediaKind,
}

#[derive(Clone, Debug)]
pub enum AcquiredDocumentOutcome {
    Acquired(AcquiredDocument),
    Rejected {
        locator: SourceLocator,
        error: Error,
    },
}

/// Acquires exactly one file, URL, or non-recursive folder selection under the
/// limits and allowlists in `config`.
pub async fn acquire_source_target(
    config: &AcquisitionConfig,
    current_dir: &Path,
    target: SourceTarget,
) -> Result<Vec<AcquiredDocument>> {
    acquire_source_target_outcomes(config, current_dir, target)
        .await?
        .into_iter()
        .map(|outcome| match outcome {
            AcquiredDocumentOutcome::Acquired(document) => Ok(document),
            AcquiredDocumentOutcome::Rejected { error, .. } => Err(error),
        })
        .collect()
}

pub async fn acquire_source_target_outcomes(
    config: &AcquisitionConfig,
    current_dir: &Path,
    target: SourceTarget,
) -> Result<Vec<AcquiredDocumentOutcome>> {
    match target {
        SourceTarget::LocalFile(path) => {
            let path = resolve_local(config, current_dir, &path)?;
            if !fs::metadata(&path).map_err(local_io)?.is_file() {
                return Err(Error::invalid("local source is not a regular file"));
            }
            Ok(vec![AcquiredDocumentOutcome::Acquired(
                read_local_document(path, config.max_document_bytes)?,
            )])
        }
        SourceTarget::LocalFolder(path) => {
            acquire_folder(config, resolve_local(config, current_dir, &path)?)
        }
        SourceTarget::HttpsUrl(value) => acquire_url(config, &value)
            .await
            .map(|document| vec![AcquiredDocumentOutcome::Acquired(document)]),
    }
}

fn resolve_local(config: &AcquisitionConfig, current_dir: &Path, input: &Path) -> Result<PathBuf> {
    let joined = if input.is_absolute() {
        input.to_path_buf()
    } else {
        current_dir.join(input)
    };
    let canonical = fs::canonicalize(&joined).map_err(local_io)?;
    for configured_root in &config.allowed_local_roots {
        let canonical_root = fs::canonicalize(configured_root).map_err(local_io)?;
        if !canonical.starts_with(&canonical_root) {
            continue;
        }
        let lexical_root = if joined.starts_with(configured_root) {
            configured_root.as_path()
        } else if joined.starts_with(&canonical_root) {
            canonical_root.as_path()
        } else {
            return Err(Error::new(
                ErrorKind::Denied,
                "local source path aliases an allowed root",
            ));
        };
        reject_symlinks_beneath(lexical_root, &joined)?;
        return Ok(canonical);
    }
    Err(Error::new(
        ErrorKind::Denied,
        "local source is outside allowed roots",
    ))
}

fn reject_symlinks_beneath(root: &Path, path: &Path) -> Result<()> {
    reject_symlink(root)?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| Error::invalid("local source path"))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(Error::invalid("local source path contains traversal"));
        };
        current.push(component);
        reject_symlink(&current)?;
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)
        .map_err(local_io)?
        .file_type()
        .is_symlink()
    {
        return Err(Error::invalid("symbolic-link sources are not allowed"));
    }
    Ok(())
}

fn acquire_folder(
    config: &AcquisitionConfig,
    folder: PathBuf,
) -> Result<Vec<AcquiredDocumentOutcome>> {
    if !fs::metadata(&folder).map_err(local_io)?.is_dir() {
        return Err(Error::invalid("local folder source is not a directory"));
    }

    let mut paths = Vec::new();
    for entry in fs::read_dir(&folder).map_err(local_io)? {
        if paths.len() == config.max_folder_entries {
            return Err(Error::limit());
        }
        paths.push(entry.map_err(local_io)?.path());
    }
    paths.sort();

    Ok(paths
        .into_iter()
        .filter(|path| media_kind_from_path(path).is_some())
        .map(|path| {
            let locator = SourceLocator::Local(path.clone());
            let result = reject_symlink(&path).and_then(|_| {
                let metadata = fs::metadata(&path).map_err(local_io)?;
                if !metadata.is_file() {
                    return Err(Error::invalid("folder contains a non-regular entry"));
                }
                read_local_document(path, config.max_document_bytes)
            });
            match result {
                Ok(document) => AcquiredDocumentOutcome::Acquired(document),
                Err(error) => AcquiredDocumentOutcome::Rejected { locator, error },
            }
        })
        .collect())
}

fn read_local_document(path: PathBuf, max_bytes: usize) -> Result<AcquiredDocument> {
    let media_kind = media_kind_from_path(&path)
        .ok_or_else(|| Error::new(ErrorKind::Unsupported, "unsupported document media kind"))?;
    let file = fs::File::open(&path).map_err(local_io)?;
    if !file.metadata().map_err(local_io)?.is_file() {
        return Err(Error::invalid("local source is not a regular file"));
    }
    let bytes = read_bounded(file, max_bytes)?;
    Ok(AcquiredDocument {
        locator: SourceLocator::Local(path),
        bytes,
        media_kind,
    })
}

fn read_bounded(reader: impl Read, max_bytes: usize) -> Result<Vec<u8>> {
    let limit = u64::try_from(max_bytes).map_err(|_| Error::limit())?;
    let mut bytes = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(local_io)?;
    if bytes.len() > max_bytes {
        return Err(Error::limit());
    }
    Ok(bytes)
}

async fn acquire_url(config: &AcquisitionConfig, value: &str) -> Result<AcquiredDocument> {
    let url = Url::parse(value).map_err(|_| Error::invalid("invalid HTTPS source URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::invalid("invalid HTTPS source URL"));
    }
    let adapter = matching_adapter(config, &url)?;
    let limit = adapter.max_bytes.min(config.max_document_bytes);
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(std::time::Duration::from_secs(
            config.provider_timeout_seconds as u64,
        ))
        .build()
        .map_err(|_| Error::new(ErrorKind::Backend, "failed to initialize HTTPS acquisition"))?;
    let mut response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "HTTPS acquisition failed"))?;
    if !response.status().is_success() {
        return Err(Error::new(
            ErrorKind::Backend,
            "HTTPS source returned an error status",
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(Error::limit());
    }
    let media_kind = media_kind_from_path(Path::new(url.path()))
        .or_else(|| media_kind_from_content_type(response.headers()))
        .ok_or_else(|| Error::new(ErrorKind::Unsupported, "unsupported document media kind"))?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "HTTPS acquisition failed"))?
    {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(Error::limit());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(AcquiredDocument {
        locator: SourceLocator::Https(url.to_string()),
        bytes,
        media_kind,
    })
}

fn matching_adapter<'a>(
    config: &'a AcquisitionConfig,
    target: &Url,
) -> Result<&'a AcquisitionUrlAdapterConfig> {
    let mut matches = config.url_adapters.values().filter(|adapter| {
        Url::parse(&adapter.base_url)
            .ok()
            .filter(valid_adapter_base)
            .is_some_and(|base| {
                same_origin(&base, target) && path_contains(base.path(), target.path())
            })
    });
    let adapter = matches
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Denied, "HTTPS source has no configured adapter"))?;
    if matches.next().is_some() {
        return Err(Error::invalid("HTTPS source matches multiple adapters"));
    }
    Ok(adapter)
}

fn valid_adapter_base(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn path_contains(base: &str, target: &str) -> bool {
    let base = base.trim_end_matches('/');
    base.is_empty()
        || target == base
        || target
            .strip_prefix(base)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn media_kind_from_path(path: &Path) -> Option<MediaKind> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "txt" => Some(MediaKind::Text),
        "md" => Some(MediaKind::Markdown),
        "pdf" => Some(MediaKind::Pdf),
        _ => None,
    }
}

fn media_kind_from_content_type(headers: &reqwest::header::HeaderMap) -> Option<MediaKind> {
    let value = headers.get(reqwest::header::CONTENT_TYPE)?.to_str().ok()?;
    match value.split(';').next()?.trim() {
        "text/plain" => Some(MediaKind::Text),
        "text/markdown" => Some(MediaKind::Markdown),
        "application/pdf" => Some(MediaKind::Pdf),
        _ => None,
    }
}

fn local_io(_: std::io::Error) -> Error {
    Error::new(ErrorKind::Backend, "local source acquisition failed")
}
