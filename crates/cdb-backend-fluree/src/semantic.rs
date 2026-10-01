//! Capability-level read-only access to an existing Fluree semantic ledger.
//! The adapter owns a Fluree client privately and deliberately exposes no
//! transaction, bootstrap, repair, or ownership-lock surface.

use crate::semantic_preparation::{export_historical_semantic_records, ExtractionLimits};
use cdb_core::{
    admission::{ChangeBatch, ExportRecord},
    contracts::{
        CapturedSnapshot, ChangeHint, ChangeHintSource, IoFuture, SemanticProjectionCapabilities,
        SemanticProjectionSnapshot, SemanticProjectionSource,
    },
    id::{AuthorityId, BackendId, GraphId, Iri, ResourceId, VersionId},
    snapshot::{Page, PageCursor, PageSize, SemanticCapture, SnapshotRef},
    Error, ErrorKind, Result, Timestamp,
};
use fluree_db_api::{
    CommitDetail, Fluree, FlureeBuilder, HistoricalLedgerView, LedgerState, NameServiceMode,
};
use fluree_db_nameservice::{file::FileNameService, NameServiceLookup, NsRecord};
use std::{path::Path, sync::Arc, time::Duration};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticLedgerOptions {
    pub backend: BackendId,
    pub authority: AuthorityId,
    pub ledger: GraphId,
}

#[derive(Clone)]
pub struct FlureeSemanticLedger {
    fluree: Arc<Fluree>,
    options: SemanticLedgerOptions,
    file_path: Option<std::path::PathBuf>,
    pub(crate) authority_cache: Arc<
        tokio::sync::Mutex<Option<(NsRecord, crate::semantic_policy::ResolvedSemanticAuthority)>>,
    >,
}

/// Fluree's file constructor synchronously takes the storage root gate during
/// WAL recovery, even with a read-only nameservice. Never run it on an async
/// executor thread: a writer holding that gate may need the same executor to
/// finish. Keep normal native recovery semantics, but isolate the blocking work.
async fn open_file_client(path: &Path) -> Result<Fluree> {
    let path = path.to_path_buf();
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        runtime.block_on(async move {
            let nameservice = NameServiceMode::ReadOnly(Arc::new(FileNameService::new(&path)));
            FlureeBuilder::file(path.to_string_lossy().into_owned())
                .without_indexing()
                .build_client_with_nameservice(nameservice)
                .await
                .map_err(map_backend)
        })
    })
    .await
    .map_err(|_| Error::new(ErrorKind::Backend, "semantic client construction failed"))?
}

impl FlureeSemanticLedger {
    /// Open an existing file-backed ledger through a read-only nameservice.
    /// This constructor cannot publish heads, create/drop ledgers, run the
    /// background indexer, or acquire a ledger-manager write lock.
    pub async fn open_file(path: impl AsRef<Path>, options: SemanticLedgerOptions) -> Result<Self> {
        let path = path.as_ref();
        let fluree = open_file_client(path).await?;
        let mut ledger = Self::open(Arc::new(fluree), options).await?;
        ledger.file_path = Some(path.to_path_buf());
        Ok(ledger)
    }

    /// Open using an already-created client. This is useful for bounded tests
    /// and embedded read capabilities; production file-backed callers should
    /// prefer [`Self::open_file`] so read-only nameservice capability is
    /// structural rather than conventional.
    pub async fn open(fluree: Arc<Fluree>, options: SemanticLedgerOptions) -> Result<Self> {
        let state = fluree
            .ledger(options.ledger.as_str())
            .await
            .map_err(map_backend)?;
        exact_head(&state)?;
        Ok(Self {
            fluree,
            options,
            file_path: None,
            authority_cache: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    pub fn options(&self) -> &SemanticLedgerOptions {
        &self.options
    }

    /// Capture the current exact source identity. History availability proves
    /// only that same `(t, commit CID)` point; no retention horizon is claimed.
    pub async fn capture_current(
        &self,
        requested_as_of: Option<Timestamp>,
    ) -> Result<SemanticCapture> {
        let state = self.current_state().await?;
        let (t, cid) = exact_head(&state)?;
        SemanticCapture::new(
            requested_as_of,
            self.options.backend.clone(),
            self.options.authority.clone(),
            self.options.ledger.clone(),
            t,
            cid.clone(),
            t,
            cid,
        )
    }

    /// Resolve and prove one requested historical transaction. Fluree's
    /// public commit builder resolves `t` to one canonical full CID and fails
    /// on rebased ambiguity; `ledger_view_at` separately proves that the
    /// requested view remains reconstructable. The availability evidence is
    /// for that exact requested point only; it is not a global retention
    /// boundary.
    pub async fn capture_at_t(
        &self,
        t: i64,
        expected_cid: Option<&ResourceId>,
        requested_as_of: Option<Timestamp>,
    ) -> Result<SemanticCapture> {
        if t < 1 {
            return Err(Error::invalid("semantic transaction"));
        }
        let (cid, _) = self.verified_historical_view(t, expected_cid).await?;
        SemanticCapture::new(
            requested_as_of,
            self.options.backend.clone(),
            self.options.authority.clone(),
            self.options.ledger.clone(),
            u64::try_from(t).map_err(|_| Error::invalid("semantic transaction"))?,
            cid.clone(),
            u64::try_from(t).map_err(|_| Error::invalid("semantic transaction"))?,
            cid,
        )
    }

    /// Resolve the exact semantic identity carried by a projection checkpoint
    /// without exporting semantic records or evaluating permissions.
    pub async fn capture_projection_snapshot(&self, pin: &SnapshotRef) -> Result<CapturedSnapshot> {
        if pin.backend() != &self.options.backend
            || pin.pin().authority() != &self.options.authority
            || pin.pin().graph() != &self.options.ledger
        {
            return Err(snapshot_divergence());
        }
        let t = pin
            .pin()
            .revision()
            .as_str()
            .parse::<i64>()
            .map_err(|_| Error::invalid("semantic transaction"))?;
        let capture = self
            .capture_at_t(t, Some(pin.pin().receipt()), None)
            .await?;
        if capture.snapshot() != pin {
            return Err(snapshot_divergence());
        }
        let detail = self.commit_detail(t).await?;
        if detail.id != pin.pin().receipt().as_str() {
            return Err(snapshot_divergence());
        }
        let as_of = semantic_commit_timestamp(
            detail
                .time
                .as_deref()
                .ok_or_else(|| Error::invalid("semantic commit timestamp"))?,
        )?;
        Ok(CapturedSnapshot {
            as_of,
            snapshot: capture.snapshot().clone(),
        })
    }

    /// Backend-internal exact state for the bounded semantic query/codec path.
    /// Keeping this crate-private prevents Fluree-native handles crossing into
    /// core, engine, or service contracts.
    async fn current_client(&self) -> Result<Arc<Fluree>> {
        if let Some(path) = &self.file_path {
            Ok(Arc::new(open_file_client(path).await?))
        } else {
            Ok(self.fluree.clone())
        }
    }

    /// Read the authoritative file nameservice on every authority check. No
    /// mtime heuristic or cached native client is a freshness witness. Embedded
    /// clients without a file binding deliberately retain the uncached path.
    pub(crate) async fn current_authority_record(&self) -> Result<Option<NsRecord>> {
        let Some(path) = &self.file_path else {
            return Ok(None);
        };
        let record = FileNameService::new(path)
            .lookup(self.options.ledger.as_str())
            .await
            .map_err(|_| Error::new(ErrorKind::Backend, "semantic nameservice unavailable"))?
            .ok_or_else(|| Error::new(ErrorKind::Backend, "semantic nameservice unavailable"))?;
        if record.retracted || record.commit_head_id.is_none() || record.commit_t < 1 {
            return Err(Error::new(
                ErrorKind::Backend,
                "semantic nameservice unavailable",
            ));
        }
        Ok(Some(record))
    }

    pub(crate) async fn current_state(&self) -> Result<LedgerState> {
        self.current_client()
            .await?
            .ledger(self.options.ledger.as_str())
            .await
            .map_err(map_backend)
    }

    /// Fetch one decoded immutable commit through Fluree's public graph API.
    /// Semantic preparation uses this to recover authoritative claim assertion
    /// transaction times; missing history is never replaced with capture time.
    pub(crate) async fn commit_detail(&self, t: i64) -> Result<CommitDetail> {
        let detail = self
            .current_client()
            .await?
            .graph(self.options.ledger.as_str())
            .commit_t(t)
            .execute()
            .await
            .map_err(map_history)?;
        if detail.t != t {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "semantic_snapshot_divergence",
            ));
        }
        Ok(detail)
    }

    /// Verify that an exact recorded capture remains reconstructable without
    /// exposing its Fluree-native historical view.
    pub async fn verify_capture_available(&self, capture: &SemanticCapture) -> Result<()> {
        self.historical_view_at(capture).await.map(drop)
    }

    pub(crate) async fn historical_view_at(
        &self,
        capture: &SemanticCapture,
    ) -> Result<HistoricalLedgerView> {
        if capture.snapshot().backend() != &self.options.backend
            || capture.snapshot().pin().authority() != &self.options.authority
            || capture.ledger() != &self.options.ledger
        {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "semantic_snapshot_divergence",
            ));
        }
        let t = i64::try_from(capture.t()).map_err(|_| Error::invalid("semantic transaction"))?;
        let (_, historical) = self
            .verified_historical_view(t, Some(capture.commit_cid()))
            .await?;
        Ok(historical)
    }

    /// Resolve `(t, CID)` on both sides of the exact historical view that the
    /// caller will consume. Any absent commit/view or changed identity fails
    /// closed as unavailable/divergent history.
    async fn verified_historical_view(
        &self,
        t: i64,
        expected_cid: Option<&ResourceId>,
    ) -> Result<(ResourceId, HistoricalLedgerView)> {
        let fluree = self.current_client().await?;
        let before = fluree
            .graph(self.options.ledger.as_str())
            .commit_t(t)
            .execute()
            .await
            .map_err(map_history)?;
        if before.t != t {
            return Err(snapshot_divergence());
        }
        let cid = ResourceId::new(before.id).map_err(|_| snapshot_divergence())?;
        if expected_cid.is_some_and(|expected| expected != &cid) {
            return Err(snapshot_divergence());
        }
        let historical = fluree
            .ledger_view_at(self.options.ledger.as_str(), t)
            .await
            .map_err(map_history)?;
        if historical.to_t() != t {
            return Err(snapshot_divergence());
        }
        let after = fluree
            .graph(self.options.ledger.as_str())
            .commit_t(t)
            .execute()
            .await
            .map_err(map_history)?;
        if after.t != t || after.id != cid.as_str() {
            return Err(snapshot_divergence());
        }
        Ok((cid, historical))
    }

    /// Prove this adapter itself did not advance the source while a bounded
    /// read operation was performed. Concurrent external writers are reported
    /// as divergence rather than silently folded into the capture.
    pub async fn verify_unchanged(&self, capture: &SemanticCapture) -> Result<()> {
        let current = self.capture_current(capture.requested_as_of()).await?;
        if current.snapshot() != capture.snapshot() {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "semantic_snapshot_divergence",
            ));
        }
        Ok(())
    }
}

struct SemanticExportSnapshot {
    identity: SnapshotRef,
    records: Vec<ExportRecord>,
}

impl SemanticProjectionSnapshot for SemanticExportSnapshot {
    fn identity(&self) -> &SnapshotRef {
        &self.identity
    }

    fn export<'a>(
        &'a self,
        cursor: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<ExportRecord>> {
        Box::pin(async move {
            let stream = ResourceId::new("semantic-export")?;
            let start = match cursor {
                None => 0,
                Some(cursor)
                    if cursor.snapshot() == &self.identity && cursor.stream() == &stream =>
                {
                    cursor
                        .position()
                        .as_str()
                        .parse::<usize>()
                        .map_err(|_| Error::invalid("semantic export cursor"))?
                }
                Some(_) => return Err(Error::invalid("semantic export cursor")),
            };
            if start > self.records.len() {
                return Err(Error::invalid("semantic export cursor"));
            }
            let end = start.saturating_add(size.get()).min(self.records.len());
            let next = (end < self.records.len()).then(|| {
                PageCursor::new(
                    self.identity.clone(),
                    stream,
                    VersionId::new(end.to_string()).expect("decimal cursor"),
                )
            });
            Page::new(
                self.records[start..end].to_vec(),
                self.identity.clone(),
                next,
                size,
            )
        })
    }
}

struct PollSemanticHints;
impl ChangeHintSource for PollSemanticHints {
    fn next(&mut self) -> IoFuture<'_, ChangeHint> {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(ChangeHint::Lagged)
        })
    }
}

impl SemanticProjectionSource for FlureeSemanticLedger {
    fn capabilities(&self) -> Result<SemanticProjectionCapabilities> {
        Ok(SemanticProjectionCapabilities {
            exact_snapshots: true,
            // The public Fluree history API proves exact snapshots but does not
            // expose a complete claim-level ordered delta stream. Coordinators
            // therefore rebuild atomically when the head changes.
            ordered_changes: false,
            closed_cutoff: true,
            complete_exports: true,
            schema: VersionId::new("ctxql-semantic-rdf/v1")?,
            algorithm: Iri::new("urn:ctxql:semantic-projection:v1")?,
        })
    }

    fn head(&self) -> IoFuture<'_, SnapshotRef> {
        Box::pin(async move { Ok(self.capture_current(None).await?.snapshot().clone()) })
    }

    fn capture(&self, requested: Option<Timestamp>) -> IoFuture<'_, CapturedSnapshot> {
        Box::pin(async move {
            if requested.is_some() {
                return Err(Error::new(
                    ErrorKind::Snapshot,
                    "semantic_timestamp_resolution_unavailable",
                ));
            }
            let capture = self.capture_current(None).await?;
            let t =
                i64::try_from(capture.t()).map_err(|_| Error::invalid("semantic transaction"))?;
            let detail = self.commit_detail(t).await?;
            let as_of = semantic_commit_timestamp(
                detail
                    .time
                    .as_deref()
                    .ok_or_else(|| Error::invalid("semantic commit timestamp"))?,
            )?;
            Ok(CapturedSnapshot {
                as_of,
                snapshot: capture.snapshot().clone(),
            })
        })
    }

    fn open_snapshot<'a>(
        &'a self,
        pin: &'a SnapshotRef,
    ) -> IoFuture<'a, Arc<dyn SemanticProjectionSnapshot>> {
        Box::pin(async move {
            if pin.backend() != &self.options.backend
                || pin.pin().authority() != &self.options.authority
                || pin.pin().graph() != &self.options.ledger
            {
                return Err(Error::new(
                    ErrorKind::Snapshot,
                    "semantic_snapshot_divergence",
                ));
            }
            let t = pin
                .pin()
                .revision()
                .as_str()
                .parse::<i64>()
                .map_err(|_| Error::invalid("semantic transaction"))?;
            let capture = self
                .capture_at_t(t, Some(pin.pin().receipt()), None)
                .await?;
            let records =
                export_historical_semantic_records(self, &capture, ExtractionLimits::default())
                    .await
                    .map_err(|reason| Error::new(ErrorKind::Backend, reason))?;
            Ok(Arc::new(SemanticExportSnapshot {
                identity: pin.clone(),
                records,
            }) as Arc<dyn SemanticProjectionSnapshot>)
        })
    }

    fn changes<'a>(
        &'a self,
        _after: &'a SnapshotRef,
        _through: &'a SnapshotRef,
        _cursor: Option<&'a PageCursor>,
        _size: PageSize,
    ) -> IoFuture<'a, Page<ChangeBatch>> {
        Box::pin(async { Err(Error::invalid("semantic ordered changes unavailable")) })
    }

    fn subscribe(&self) -> IoFuture<'_, Box<dyn ChangeHintSource>> {
        Box::pin(async { Ok(Box::new(PollSemanticHints) as Box<dyn ChangeHintSource>) })
    }
}

pub(crate) fn semantic_commit_timestamp(value: &str) -> Result<Timestamp> {
    let normalized = if let Some(dot) = value.find('.') {
        let fraction_end = value[dot + 1..]
            .find(|c: char| !c.is_ascii_digit())
            .map(|offset| dot + 1 + offset)
            .unwrap_or(value.len());
        let mut millis = value[dot + 1..fraction_end]
            .chars()
            .take(3)
            .collect::<String>();
        while millis.len() < 3 {
            millis.push('0');
        }
        format!("{}.{}{}", &value[..dot], millis, &value[fraction_end..])
    } else {
        value.to_owned()
    };
    Timestamp::parse(&normalized).map_err(|_| Error::invalid("semantic commit timestamp"))
}

fn exact_head(state: &LedgerState) -> Result<(u64, ResourceId)> {
    let t = u64::try_from(state.t()).map_err(|_| Error::invalid("semantic transaction"))?;
    let cid = state
        .head_commit_id
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::Snapshot, "semantic capture has no commit CID"))?;
    Ok((t, ResourceId::new(cid.to_string())?))
}

fn snapshot_divergence() -> Error {
    Error::new(ErrorKind::Snapshot, "semantic_snapshot_divergence")
}

fn map_backend(error: fluree_db_api::ApiError) -> Error {
    Error::new(ErrorKind::Backend, error.to_string())
}

fn map_history(_error: fluree_db_api::ApiError) -> Error {
    Error::new(ErrorKind::Snapshot, "semantic_history_unavailable")
}
