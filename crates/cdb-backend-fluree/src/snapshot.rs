use crate::{backend::map, history, journal, native::NativeStore, options::AuthorityOptions};
use cdb_core::{admission::*, artifact::*, contracts::*, id::*, snapshot::*, Error, Result};

pub(crate) struct ExactSnapshot {
    pub native: NativeStore,
    pub options: AuthorityOptions,
    pub identity: SnapshotRef,
}
pub fn export_stream() -> ResourceId {
    ResourceId::new("urn:ctxql:fluree:export:v1").expect("constant")
}
pub fn changes_stream(after: &SnapshotRef) -> ResourceId {
    let mut bytes = Vec::new();
    for s in [
        after.backend().as_str(),
        after.pin().authority().as_str(),
        after.pin().graph().as_str(),
        after.pin().revision().as_str(),
        after.pin().receipt().as_str(),
    ] {
        bytes.extend_from_slice(&(s.len() as u64).to_be_bytes());
        bytes.extend_from_slice(s.as_bytes());
    }
    ResourceId::new(format!(
        "urn:ctxql:fluree:changes:{}",
        ContentHash::of_bytes(&bytes).as_str()
    ))
    .expect("hash")
}
pub(crate) fn page<T: Clone>(
    items: &[T],
    target: &SnapshotRef,
    stream: ResourceId,
    cursor: Option<&PageCursor>,
    size: PageSize,
) -> Result<Page<T>> {
    let start = if let Some(c) = cursor {
        if c.snapshot() != target || c.stream() != &stream {
            return Err(Error::invalid("foreign cursor"));
        }
        let n = c
            .position()
            .as_str()
            .parse::<usize>()
            .map_err(|_| Error::invalid("cursor position"))?;
        if n == 0 || n.to_string() != c.position().as_str() || n >= items.len() {
            return Err(Error::invalid("cursor range"));
        }
        n
    } else {
        0
    };
    let end = start.saturating_add(size.get()).min(items.len());
    let next = if end < items.len() {
        Some(PageCursor::new(
            target.clone(),
            stream,
            VersionId::new(end.to_string())?,
        ))
    } else {
        None
    };
    Page::new(items[start..end].to_vec(), target.clone(), next, size)
}
impl BackendSnapshot for ExactSnapshot {
    fn identity(&self) -> &SnapshotRef {
        &self.identity
    }
    fn resource<'a>(&'a self, id: &'a ResourceId) -> IoFuture<'a, Option<DependencyRecord>> {
        Box::pin(async move {
            let rows = self
                .native
                .read_records(
                    &history::pin(&self.identity).map_err(map)?,
                    Some(("record".into(), resource_key(id.as_str()))),
                )
                .await
                .map_err(map)?;
            match rows
                .first()
                .map(|r| journal::decode(r, self.options.codec_limits))
                .transpose()
                .map_err(map)?
            {
                Some(ExportRecord::Resource(r)) => Ok(Some(r)),
                _ => Ok(None),
            }
        })
    }
    fn artifact<'a>(&'a self, r: &'a ArtifactRef) -> IoFuture<'a, Option<PublishedArtifact>> {
        Box::pin(async move {
            let rows = self
                .native
                .read_records(
                    &history::pin(&self.identity).map_err(map)?,
                    Some(("record".into(), artifact_key(r))),
                )
                .await
                .map_err(map)?;
            match rows
                .first()
                .map(|r| journal::decode(r, self.options.codec_limits))
                .transpose()
                .map_err(map)?
            {
                Some(ExportRecord::Artifact(a)) if a.reference() == r => Ok(Some(a)),
                Some(ExportRecord::Artifact(_)) => Err(Error::new(
                    cdb_core::ErrorKind::Conflict,
                    "artifact reference mismatch",
                )),
                None => Ok(None),
                _ => Err(Error::invalid("artifact key mismatch")),
            }
        })
    }
    fn export<'a>(
        &'a self,
        cursor: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<ExportRecord>> {
        Box::pin(async move {
            let rows = self
                .native
                .read_records(&history::pin(&self.identity).map_err(map)?, None)
                .await
                .map_err(map)?;
            let records = rows
                .iter()
                .filter(|r| r.kind == "record")
                .map(|r| journal::decode(r, self.options.codec_limits))
                .collect::<crate::native::NativeResult<Vec<_>>>()
                .map_err(map)?;
            page(&records, &self.identity, export_stream(), cursor, size)
        })
    }
}
