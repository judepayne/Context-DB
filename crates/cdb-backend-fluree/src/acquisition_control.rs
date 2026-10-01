//! Append-only P6 operational journal owned by the configured Control authority.

use crate::FlureeControlLedger;
use cdb_core::acquisition::{AcquisitionControl, BundlePrepared, PreparedSupersededAbsent};
use cdb_core::contracts::IoFuture;
use cdb_core::id::BundleId;
use cdb_core::review::{ReviewAdmissionReceipt, ReviewBundlePrepared};
use cdb_core::semantic_admission::{ProjectionReceipt, SemanticAdmissionReceipt};
use cdb_core::{CanonicalValue as V, Error, ErrorKind, Limits, Result};
use fs2::FileExt;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

struct JournalState {
    prepared: BTreeMap<BundleId, BundlePrepared>,
    review_prepared: BTreeMap<BundleId, ReviewBundlePrepared>,
    admissions: BTreeMap<BundleId, SemanticAdmissionReceipt>,
    review_admissions: BTreeMap<BundleId, ReviewAdmissionReceipt>,
    projections: BTreeMap<BundleId, ProjectionReceipt>,
    superseded_absent: BTreeMap<BundleId, PreparedSupersededAbsent>,
}

pub struct FlureeAcquisitionControl {
    path: PathBuf,
    limits: Limits,
    max_bytes: usize,
    prepared: Mutex<BTreeMap<BundleId, BundlePrepared>>,
    review_prepared: Mutex<BTreeMap<BundleId, ReviewBundlePrepared>>,
    admissions: Mutex<BTreeMap<BundleId, SemanticAdmissionReceipt>>,
    review_admissions: Mutex<BTreeMap<BundleId, ReviewAdmissionReceipt>>,
    projections: Mutex<BTreeMap<BundleId, ProjectionReceipt>>,
    superseded_absent: Mutex<BTreeMap<BundleId, PreparedSupersededAbsent>>,
}

impl FlureeAcquisitionControl {
    pub fn open(control: &FlureeControlLedger, max_bytes: usize) -> Result<Self> {
        if max_bytes == 0 {
            return Err(Error::limit());
        }
        let path = control
            .backend()
            .options
            .path
            .join("p6-acquisition-control-v1.jsonl");
        let mut file = open_journal(&path)?;
        file.lock_shared().map_err(storage)?;
        let state = read_state(&mut file, max_bytes, control.backend().options.codec_limits)?;
        file.unlock().map_err(storage)?;
        Ok(Self {
            path,
            limits: control.backend().options.codec_limits,
            max_bytes,
            prepared: Mutex::new(state.prepared),
            review_prepared: Mutex::new(state.review_prepared),
            admissions: Mutex::new(state.admissions),
            review_admissions: Mutex::new(state.review_admissions),
            projections: Mutex::new(state.projections),
            superseded_absent: Mutex::new(state.superseded_absent),
        })
    }

    fn append(&self, kind: &str, bundle: &BundleId, payload: V) -> Result<()> {
        let record = V::object([
            ("schema".into(), V::string("ctxql-acquisition-control/v1")),
            ("kind".into(), V::string(kind)),
            ("bundle_id".into(), V::string(bundle.as_str())),
            ("payload".into(), payload),
        ])?;
        let mut bytes = record.canonical_bytes(self.limits)?;
        bytes.push(b'\n');
        if bytes.len() > self.max_bytes {
            return Err(Error::limit());
        }
        let mut file = open_journal(&self.path)?;
        file.lock_exclusive().map_err(storage)?;
        let length =
            usize::try_from(file.metadata().map_err(storage)?.len()).map_err(|_| Error::limit())?;
        if length.checked_add(bytes.len()).ok_or_else(Error::limit)? > self.max_bytes {
            file.unlock().map_err(storage)?;
            return Err(Error::limit());
        }
        file.seek(SeekFrom::End(0)).map_err(storage)?;
        file.write_all(&bytes).map_err(storage)?;
        file.sync_data().map_err(storage)?;
        file.unlock().map_err(storage)?;
        Ok(())
    }

    pub async fn review_admission(
        &self,
        bundle: &BundleId,
    ) -> Result<Option<ReviewAdmissionReceipt>> {
        Ok(self
            .review_admissions
            .lock()
            .map_err(|_| storage_message())?
            .get(bundle)
            .cloned())
    }

    pub async fn append_review_admission(
        &self,
        bundle: &BundleId,
        receipt: &ReviewAdmissionReceipt,
    ) -> Result<()> {
        let mut admissions = self
            .review_admissions
            .lock()
            .map_err(|_| storage_message())?;
        if let Some(existing) = admissions.get(bundle) {
            return if existing == receipt {
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::Conflict,
                    "control review admission conflict",
                ))
            };
        }
        let prepared = self
            .review_prepared
            .lock()
            .map_err(|_| storage_message())?
            .get(bundle)
            .cloned()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Conflict,
                    "control review admission missing prepared record",
                )
            })?;
        receipt.verify_prepared(&prepared)?;
        self.append("review_admission", bundle, receipt.projection())?;
        admissions.insert(bundle.clone(), receipt.clone());
        Ok(())
    }
}

impl AcquisitionControl for FlureeAcquisitionControl {
    fn append_prepared<'a>(&'a self, prepared: &'a BundlePrepared) -> IoFuture<'a, ()> {
        Box::pin(async move {
            prepared.validate()?;
            let mut indexed = self.prepared.lock().map_err(|_| storage_message())?;
            if let Some(existing) = indexed.get(&prepared.bundle_id) {
                return if existing == prepared {
                    Ok(())
                } else {
                    Err(Error::new(ErrorKind::Conflict, "control prepared conflict"))
                };
            }
            self.append(
                "bundle_prepared",
                &prepared.bundle_id,
                prepared.projection(),
            )?;
            indexed.insert(prepared.bundle_id.clone(), prepared.clone());
            Ok(())
        })
    }

    fn prepared<'a>(&'a self, bundle: &'a BundleId) -> IoFuture<'a, Option<BundlePrepared>> {
        Box::pin(async move {
            Ok(self
                .prepared
                .lock()
                .map_err(|_| storage_message())?
                .get(bundle)
                .cloned())
        })
    }

    fn prepared_records(&self) -> IoFuture<'_, Vec<BundlePrepared>> {
        Box::pin(async move {
            Ok(self
                .prepared
                .lock()
                .map_err(|_| storage_message())?
                .values()
                .cloned()
                .collect())
        })
    }

    fn admission<'a>(
        &'a self,
        bundle: &'a BundleId,
    ) -> IoFuture<'a, Option<SemanticAdmissionReceipt>> {
        Box::pin(async move {
            Ok(self
                .admissions
                .lock()
                .map_err(|_| storage_message())?
                .get(bundle)
                .cloned())
        })
    }

    fn append_admission<'a>(
        &'a self,
        bundle: &'a BundleId,
        receipt: &'a SemanticAdmissionReceipt,
    ) -> IoFuture<'a, ()> {
        Box::pin(async move {
            let mut admissions = self.admissions.lock().map_err(|_| storage_message())?;
            if let Some(existing) = admissions.get(bundle) {
                return if existing == receipt {
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorKind::Conflict,
                        "control admission conflict",
                    ))
                };
            }
            self.append("semantic_admission", bundle, receipt.projection())?;
            admissions.insert(bundle.clone(), receipt.clone());
            Ok(())
        })
    }

    fn append_projection<'a>(
        &'a self,
        bundle: &'a BundleId,
        receipt: &'a ProjectionReceipt,
    ) -> IoFuture<'a, ()> {
        Box::pin(async move {
            let mut projections = self.projections.lock().map_err(|_| storage_message())?;
            if let Some(existing) = projections.get(bundle) {
                return if existing == receipt {
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorKind::Conflict,
                        "control projection conflict",
                    ))
                };
            }
            self.append("projection", bundle, receipt.projection())?;
            projections.insert(bundle.clone(), receipt.clone());
            Ok(())
        })
    }

    fn append_review_prepared<'a>(
        &'a self,
        prepared: &'a ReviewBundlePrepared,
    ) -> IoFuture<'a, ()> {
        Box::pin(async move {
            prepared.validate()?;
            let mut indexed = self.review_prepared.lock().map_err(|_| storage_message())?;
            if let Some(existing) = indexed.get(&prepared.bundle_id) {
                return if existing == prepared {
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorKind::Conflict,
                        "control review prepared conflict",
                    ))
                };
            }
            self.append(
                "review_bundle_prepared",
                &prepared.bundle_id,
                prepared.projection(),
            )?;
            indexed.insert(prepared.bundle_id.clone(), prepared.clone());
            Ok(())
        })
    }

    fn review_prepared<'a>(
        &'a self,
        bundle: &'a BundleId,
    ) -> IoFuture<'a, Option<ReviewBundlePrepared>> {
        Box::pin(async move {
            Ok(self
                .review_prepared
                .lock()
                .map_err(|_| storage_message())?
                .get(bundle)
                .cloned())
        })
    }

    fn review_prepared_records(&self) -> IoFuture<'_, Vec<ReviewBundlePrepared>> {
        Box::pin(async move {
            Ok(self
                .review_prepared
                .lock()
                .map_err(|_| storage_message())?
                .values()
                .cloned()
                .collect())
        })
    }

    fn review_admission<'a>(
        &'a self,
        bundle: &'a BundleId,
    ) -> IoFuture<'a, Option<ReviewAdmissionReceipt>> {
        Box::pin(async move { FlureeAcquisitionControl::review_admission(self, bundle).await })
    }

    fn append_review_admission<'a>(
        &'a self,
        bundle: &'a BundleId,
        receipt: &'a ReviewAdmissionReceipt,
    ) -> IoFuture<'a, ()> {
        Box::pin(async move {
            FlureeAcquisitionControl::append_review_admission(self, bundle, receipt).await
        })
    }

    fn append_superseded_absent<'a>(
        &'a self,
        record: &'a PreparedSupersededAbsent,
    ) -> IoFuture<'a, ()> {
        Box::pin(async move {
            record.validate()?;
            let mut indexed = self
                .superseded_absent
                .lock()
                .map_err(|_| storage_message())?;
            if let Some(existing) = indexed.get(&record.predecessor_bundle_id) {
                return if existing == record {
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorKind::Conflict,
                        "control prepared supersession conflict",
                    ))
                };
            }
            self.append(
                "prepared_superseded_absent",
                &record.predecessor_bundle_id,
                record.projection(),
            )?;
            indexed.insert(record.predecessor_bundle_id.clone(), record.clone());
            Ok(())
        })
    }

    fn superseded_absent<'a>(
        &'a self,
        predecessor: &'a BundleId,
    ) -> IoFuture<'a, Option<PreparedSupersededAbsent>> {
        Box::pin(async move {
            Ok(self
                .superseded_absent
                .lock()
                .map_err(|_| storage_message())?
                .get(predecessor)
                .cloned())
        })
    }

    fn superseded_absent_records(&self) -> IoFuture<'_, Vec<PreparedSupersededAbsent>> {
        Box::pin(async move {
            Ok(self
                .superseded_absent
                .lock()
                .map_err(|_| storage_message())?
                .values()
                .cloned()
                .collect())
        })
    }
}

fn read_state(file: &mut File, max_bytes: usize, limits: Limits) -> Result<JournalState> {
    let length =
        usize::try_from(file.metadata().map_err(storage)?.len()).map_err(|_| Error::limit())?;
    if length > max_bytes {
        return Err(Error::limit());
    }
    file.seek(SeekFrom::Start(0)).map_err(storage)?;
    let mut bytes = Vec::with_capacity(length);
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(storage)?;
    if bytes.len() > max_bytes {
        return Err(Error::limit());
    }
    let mut prepared = BTreeMap::new();
    let mut review_prepared = BTreeMap::new();
    let mut admissions = BTreeMap::new();
    let mut review_admissions = BTreeMap::new();
    let mut projections = BTreeMap::new();
    let mut superseded_absent = BTreeMap::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let value = V::parse(line, limits)?;
        value.closed(&["schema", "kind", "bundle_id", "payload"], &[])?;
        if value.field("schema")?.as_str()? != "ctxql-acquisition-control/v1" {
            return Err(Error::invalid("acquisition control schema"));
        }
        let bundle = BundleId::new(value.field("bundle_id")?.as_str()?)?;
        match value.field("kind")?.as_str()? {
            "bundle_prepared" => {
                let record = BundlePrepared::from_value(value.field("payload")?)?;
                if record.bundle_id != bundle
                    || prepared
                        .insert(bundle, record.clone())
                        .is_some_and(|old| old != record)
                {
                    return Err(Error::new(ErrorKind::Conflict, "control prepared conflict"));
                }
            }
            "review_bundle_prepared" => {
                let record = ReviewBundlePrepared::from_value(value.field("payload")?)?;
                if record.bundle_id != bundle
                    || review_prepared
                        .insert(bundle, record.clone())
                        .is_some_and(|old| old != record)
                {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "control review prepared conflict",
                    ));
                }
            }
            "semantic_admission" => {
                let receipt = SemanticAdmissionReceipt::from_value(value.field("payload")?)?;
                if admissions
                    .insert(bundle, receipt.clone())
                    .is_some_and(|old| old != receipt)
                {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "control admission conflict",
                    ));
                }
            }
            "review_admission" => {
                let receipt = ReviewAdmissionReceipt::from_value(value.field("payload")?)?;
                if review_admissions
                    .insert(bundle, receipt.clone())
                    .is_some_and(|old| old != receipt)
                {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "control review admission conflict",
                    ));
                }
            }
            "projection" => {
                let receipt = ProjectionReceipt::from_value(value.field("payload")?)?;
                if projections
                    .insert(bundle, receipt.clone())
                    .is_some_and(|old| old != receipt)
                {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "control projection conflict",
                    ));
                }
            }
            "prepared_superseded_absent" => {
                let record = PreparedSupersededAbsent::from_value(value.field("payload")?)?;
                if record.predecessor_bundle_id != bundle
                    || superseded_absent
                        .insert(bundle, record.clone())
                        .is_some_and(|old| old != record)
                {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "control prepared supersession conflict",
                    ));
                }
            }
            _ => return Err(Error::invalid("acquisition control record kind")),
        }
    }
    for (bundle, receipt) in &review_admissions {
        let prepared_record = review_prepared.get(bundle).ok_or_else(|| {
            Error::new(
                ErrorKind::Conflict,
                "control review admission missing prepared record",
            )
        })?;
        receipt.verify_prepared(prepared_record)?;
    }
    Ok(JournalState {
        prepared,
        review_prepared,
        admissions,
        review_admissions,
        projections,
        superseded_absent,
    })
}

fn open_journal(path: &PathBuf) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path).map_err(storage)
}

fn storage(error: impl std::fmt::Display) -> Error {
    let _ = error;
    storage_message()
}
fn storage_message() -> Error {
    Error::new(ErrorKind::Backend, "acquisition control storage failure")
}
