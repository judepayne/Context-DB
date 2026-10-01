//! Drain fixture/admission WAL cleanup before measuring a separate read-only operation.
//! Call only after all setup clients have been dropped; this is not a writer lock.

use std::{path::Path, time::Duration};

pub async fn wait_for_wal_cleanup(root: &Path, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let mut pending = Vec::new();
        for store in ["semantic", "control"] {
            let directory = root.join(store).join(".fluree-wal");
            let entries = match std::fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("cannot inspect {}: {error}", directory.display()),
            };
            for entry in entries {
                let entry = entry.expect("cannot inspect WAL entry");
                // LOCK is persistent. Every other entry, including later-numbered
                // segments and temporary files, must finish retiring before capture.
                if entry.file_name() != "LOCK" {
                    pending.push(entry.path());
                }
            }
        }
        if pending.is_empty() {
            return;
        }
        pending.sort();
        assert!(
            tokio::time::Instant::now() < deadline,
            "setup WAL cleanup did not finish: {pending:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn absent_wals_and_persistent_locks_are_quiescent() {
        let root = tempfile::tempdir().unwrap();
        wait_for_wal_cleanup(root.path(), Duration::ZERO).await;
        for store in ["semantic", "control"] {
            let directory = root.path().join(store).join(".fluree-wal");
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("LOCK"), b"").unwrap();
        }
        wait_for_wal_cleanup(root.path(), Duration::ZERO).await;
    }

    #[tokio::test]
    #[should_panic(expected = "setup WAL cleanup did not finish")]
    async fn later_segment_without_segment_one_cannot_pass() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("semantic/.fluree-wal");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("00000002.wal"), b"pending").unwrap();
        wait_for_wal_cleanup(root.path(), Duration::ZERO).await;
    }

    #[tokio::test]
    #[should_panic(expected = "setup WAL cleanup did not finish")]
    async fn control_temporary_segment_cannot_pass() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("control/.fluree-wal");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("00000003.wal.tmp"), b"pending").unwrap();
        wait_for_wal_cleanup(root.path(), Duration::ZERO).await;
    }
}
