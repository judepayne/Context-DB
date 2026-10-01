//! Content-free, immutable acquisition work links in the Control storage boundary.
//! Payloads belong to the source/evidence store. Publication uses rename-no-replace
//! and directory fsync: interruption leaves either no link or a complete link.

use cdb_core::{
    id::{ContentHash, JobId},
    CanonicalValue as V, Error, ErrorKind, Limits, Result,
};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(crate) struct WorkCheckpoints {
    root: PathBuf,
    max_bytes: usize,
}

impl WorkCheckpoints {
    pub fn open(control_root: &Path, max_bytes: usize) -> Result<Self> {
        let root = control_root.join("acquisition-work-v2");
        match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(Error::invalid("unsafe acquisition checkpoint directory"))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(&root).map_err(storage)?;
                fs::File::open(control_root)
                    .and_then(|file| file.sync_all())
                    .map_err(storage)?;
            }
            Err(error) => return Err(storage(error)),
        }
        Ok(Self { root, max_bytes })
    }

    fn path(&self, job: &JobId, stage: &str) -> Result<PathBuf> {
        if !matches!(
            stage,
            "capture"
                | "evaluation"
                | "review"
                | "business"
                | "result"
                | "result_review"
                | "artifact_pages"
                | "graph_artifact_pages"
                | "graph_workspace"
                | "graph_context"
                | "graph_capability"
                | "graph_capture"
                | "party_seed"
        ) {
            return Err(Error::invalid("unknown acquisition checkpoint stage"));
        }
        let key = ContentHash::of_bytes(job.as_str().as_bytes());
        Ok(self
            .root
            .join(format!("{}-{stage}.json", &key.as_str()[7..])))
    }

    /// Internal discovery only; callers must authorize jobs before releasing them.
    pub fn jobs(&self) -> Result<Vec<JobId>> {
        let mut jobs = std::collections::BTreeSet::new();
        let mut used = 0u64;
        for entry in fs::read_dir(&self.root).map_err(storage)? {
            let entry = entry.map_err(storage)?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(storage)?;
            used = used.checked_add(metadata.len()).ok_or_else(Error::limit)?;
            if used > self.max_bytes as u64 {
                return Err(Error::limit());
            }
            // Unpublished NamedTempFile objects are safe crash orphans, not links.
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".tmp"))
            {
                continue;
            }
            if let Some((job, _, _)) = self.read_link(&entry.path())? {
                jobs.insert(job.as_str().to_owned());
            }
        }
        jobs.into_iter().map(JobId::new).collect()
    }

    pub fn get(&self, job: &JobId, stage: &str) -> Result<Option<ContentHash>> {
        self.read_link(&self.path(job, stage)?)
            .map(|link| link.map(|(_, _, root)| root))
    }

    fn read_link(&self, path: &Path) -> Result<Option<(JobId, String, ContentHash)>> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(storage(error)),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4096 {
            return Err(Error::invalid("unsafe acquisition checkpoint"));
        }
        let mut bytes = Vec::new();
        fs::File::open(path)
            .map_err(storage)?
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(storage)?;
        if bytes.len() > 4096 {
            return Err(Error::limit());
        }
        let value = V::parse(&bytes, Limits::default())?;
        value.closed(&["schema", "job_id", "stage", "root"], &[])?;
        let job = JobId::new(value.field("job_id")?.as_str()?)?;
        let stage = value.field("stage")?.as_str()?;
        if value.field("schema")?.as_str()? != "ctxql-acquisition-work-link/v1"
            || self.path(&job, stage)? != path
        {
            return Err(Error::invalid("acquisition checkpoint binding"));
        }
        Ok(Some((
            job,
            stage.to_owned(),
            ContentHash::parse(value.field("root")?.as_str()?)?,
        )))
    }

    pub fn put(&self, job: &JobId, stage: &str, root: &ContentHash) -> Result<()> {
        if let Some(existing) = self.get(job, stage)? {
            return if &existing == root {
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::Conflict,
                    "acquisition checkpoint differs",
                ))
            };
        }
        let value = V::object([
            ("schema".into(), V::string("ctxql-acquisition-work-link/v1")),
            ("job_id".into(), V::string(job.as_str())),
            ("stage".into(), V::string(stage)),
            ("root".into(), V::string(root.as_str())),
        ])?;
        let bytes = value.canonical_bytes(Limits::default())?;
        let mut used = bytes.len() as u64;
        for entry in fs::read_dir(&self.root).map_err(storage)? {
            used = used
                .checked_add(entry.map_err(storage)?.metadata().map_err(storage)?.len())
                .ok_or_else(Error::limit)?;
            if used > self.max_bytes as u64 {
                return Err(Error::limit());
            }
        }
        let mut temporary = tempfile::NamedTempFile::new_in(&self.root).map_err(storage)?;
        temporary.write_all(&bytes).map_err(storage)?;
        temporary.as_file().sync_all().map_err(storage)?;
        match temporary.persist_noclobber(self.path(job, stage)?) {
            Ok(_) => {}
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                if self.get(job, stage)?.as_ref() != Some(root) {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "acquisition checkpoint differs",
                    ));
                }
            }
            Err(error) => return Err(storage(error.error)),
        }
        fs::File::open(&self.root)
            .and_then(|file| file.sync_all())
            .map_err(storage)
    }
}

fn storage(_: std::io::Error) -> Error {
    Error::new(ErrorKind::Backend, "acquisition checkpoint storage")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checkpoint_is_idempotent_bound_and_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let job = JobId::new("job:one").unwrap();
        let root = ContentHash::of_bytes(b"evaluation");
        let checkpoints = WorkCheckpoints::open(directory.path(), 8192).unwrap();
        assert_eq!(checkpoints.get(&job, "evaluation").unwrap(), None);
        checkpoints.put(&job, "evaluation", &root).unwrap();
        for stage in [
            "graph_artifact_pages",
            "graph_workspace",
            "graph_context",
            "graph_capability",
            "graph_capture",
            "party_seed",
        ] {
            checkpoints.put(&job, stage, &root).unwrap();
        }
        checkpoints.put(&job, "evaluation", &root).unwrap();
        assert!(checkpoints
            .put(&job, "evaluation", &ContentHash::of_bytes(b"changed"))
            .is_err());
        let reopened = WorkCheckpoints::open(directory.path(), 8192).unwrap();
        assert_eq!(
            reopened.get(&job, "evaluation").unwrap(),
            Some(root.clone())
        );
        for stage in [
            "graph_artifact_pages",
            "graph_workspace",
            "graph_context",
            "graph_capability",
            "graph_capture",
            "party_seed",
        ] {
            assert_eq!(reopened.get(&job, stage).unwrap(), Some(root.clone()));
        }
        assert!(reopened.get(&job, "../escape").is_err());
        assert_eq!(reopened.jobs().unwrap(), vec![job]);
    }

    #[test]
    fn discovery_deduplicates_jobs_and_rejects_forged_filenames() {
        let directory = tempfile::tempdir().unwrap();
        let checkpoints = WorkCheckpoints::open(directory.path(), 16384).unwrap();
        let job = JobId::new("job:one").unwrap();
        let other = JobId::new("job:two").unwrap();
        let root = ContentHash::of_bytes(b"payload");
        checkpoints.put(&job, "capture", &root).unwrap();
        checkpoints.put(&job, "evaluation", &root).unwrap();
        assert_eq!(checkpoints.jobs().unwrap(), vec![job.clone()]);
        fs::copy(
            checkpoints.path(&job, "capture").unwrap(),
            checkpoints.path(&other, "capture").unwrap(),
        )
        .unwrap();
        assert!(checkpoints.jobs().is_err());
        assert!(checkpoints.get(&other, "capture").is_err());
    }

    #[test]
    fn discovery_bounds_links_and_ignores_unpublished_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let checkpoints = WorkCheckpoints::open(directory.path(), 8192).unwrap();
        let mut orphan = tempfile::NamedTempFile::new_in(&checkpoints.root).unwrap();
        orphan.write_all(b"unfinished").unwrap();
        assert!(checkpoints.jobs().unwrap().is_empty());
        fs::write(checkpoints.root.join("forged.json"), vec![b'x'; 4097]).unwrap();
        assert!(checkpoints.jobs().is_err());
    }
}
