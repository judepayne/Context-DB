use serde_json::json;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static LOG_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Explicit opt-in paths for one Pi process. Pi's native JSONL sessions can
/// contain prompts, reasoning, tool arguments/results, and source content.
#[derive(Clone, Debug)]
pub struct SessionLogging {
    pub root: PathBuf,
}

pub(crate) struct ProcessLog {
    session_dir: PathBuf,
    diagnostic_path: PathBuf,
    diagnostic: Mutex<File>,
    degraded_warning_emitted: AtomicBool,
}

impl ProcessLog {
    pub(crate) fn create(
        config: &SessionLogging,
        component: &'static str,
    ) -> std::io::Result<Self> {
        prepare_private_directory(&config.root)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let run = format!(
            "{component}-{now}-{}-{}",
            std::process::id(),
            LOG_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let session_dir = config.root.join(format!("pi-{run}"));
        create_private_directory(&session_dir)?;
        let diagnostic_path = config.root.join(format!("host-{run}.jsonl"));
        let diagnostic = create_private_file(&diagnostic_path)?;
        let log = Self {
            session_dir,
            diagnostic_path,
            diagnostic: Mutex::new(diagnostic),
            degraded_warning_emitted: AtomicBool::new(false),
        };
        log.record("process_log_created", "ok");
        Ok(log)
    }

    pub(crate) fn session_dir(&self) -> &Path {
        &self.session_dir
    }

    pub(crate) fn diagnostic_path(&self) -> &Path {
        &self.diagnostic_path
    }

    pub(crate) fn owns_session_file(&self, path: &Path) -> bool {
        path.is_absolute() && path.starts_with(&self.session_dir)
    }

    /// Content-free lifecycle diagnostics only. Values must be fixed host
    /// categories, never provider text, tool payloads, paths, or credentials.
    pub(crate) fn record(&self, event: &'static str, outcome: &'static str) {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let record = json!({
            "schema": "ctxql.pi-host-diagnostic/v1",
            "timestamp_ms": timestamp_ms,
            "event": event,
            "outcome": outcome,
        });
        let result = self.diagnostic.lock().map_err(|_| ()).and_then(|mut file| {
            serde_json::to_writer(&mut *file, &record).map_err(|_| ())?;
            file.write_all(b"\n").map_err(|_| ())?;
            file.flush().map_err(|_| ())
        });
        if result.is_err() && !self.degraded_warning_emitted.swap(true, Ordering::Relaxed) {
            eprintln!("WARNING: Pi host diagnostic logging has failed; retained diagnostics may be incomplete.");
        }
    }
}

fn prepare_private_directory(path: &Path) -> std::io::Result<()> {
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "session log directory must be absolute",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_directory(path, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(path)
        }
        Err(error) => Err(error),
    }
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    validate_private_directory(path, &metadata)
}

fn validate_private_directory(path: &Path, metadata: &fs::Metadata) -> std::io::Result<()> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsafe session log directory: {}", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("session log directory is not private: {}", path.display()),
            ));
        }
    }
    Ok(())
}

fn create_private_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_private_unique_session_and_diagnostic_paths() {
        let parent = std::env::temp_dir().join(format!(
            "ctxql-session-log-test-{}-{}",
            std::process::id(),
            LOG_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let log = ProcessLog::create(
            &SessionLogging {
                root: parent.clone(),
            },
            "chat",
        )
        .unwrap();
        assert!(log.session_dir().is_dir());
        assert!(log.diagnostic_path().is_file());
        let contents = fs::read_to_string(log.diagnostic_path()).unwrap();
        assert!(contents.contains("process_log_created"));
        assert!(!contents.contains(&parent.display().to_string()));
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_private_existing_root() {
        use std::os::unix::fs::PermissionsExt;
        let parent = std::env::temp_dir().join(format!(
            "ctxql-session-log-permissions-{}-{}",
            std::process::id(),
            LOG_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ProcessLog::create(
            &SessionLogging {
                root: parent.clone()
            },
            "chat"
        )
        .is_err());
        fs::remove_dir(parent).unwrap();
    }
}
