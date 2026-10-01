//! Extract-only graph reads over an isolated Semantic store copy.
//!
//! This module deliberately does not construct `Service`, `AcquisitionService`,
//! a Semantic writer, a projection coordinator, or recovery machinery. Query
//! execution is supplied as a narrow closure so the graph-query adapter can use
//! the isolated ledger and pinned capture without gaining mutation capability.

use cdb_backend_fluree::{FlureeSemanticLedger, SemanticLedgerOptions};
use cdb_core::{
    contracts::IoFuture,
    snapshot::{ProjectionCheckpoint, SemanticCapture},
    Error, ErrorKind, Result,
};
use cdb_projection_redb::{GenerationOptions, RedbProjection};
use std::{
    fs,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tempfile::TempDir;

/// A current-authority check against the original configured stores.
///
/// Implementations must not infer authority from the isolated copy: the copy is
/// only pinned query data and cannot observe policy revocation.
pub(crate) trait CurrentGraphReadAuthority: Send + Sync {
    fn reauthorize(&self) -> IoFuture<'_, ()>;
}

/// One exact, private Semantic snapshot used only for extract-only graph reads.
pub(crate) struct IsolatedGraphReadSnapshot {
    _root: TempDir,
    semantic: Arc<FlureeSemanticLedger>,
    projection: Arc<RedbProjection>,
    capture: SemanticCapture,
}

impl IsolatedGraphReadSnapshot {
    /// Copy one stable current Semantic store into a private temporary directory.
    /// The source is checked on both sides of the copy, and the copied ledger
    /// must reopen at that exact capture. A concurrent source-head change fails
    /// closed instead of producing a mixed filesystem snapshot.
    pub(crate) async fn copy_from(
        original: &FlureeSemanticLedger,
        source: &Path,
        options: SemanticLedgerOptions,
        projection_source: &Path,
        projection_binding: ProjectionCheckpoint,
    ) -> Result<Self> {
        let before = original.capture_current(None).await?;
        let root = tempfile::tempdir().map_err(|_| {
            Error::new(
                ErrorKind::Backend,
                "extract-only graph snapshot unavailable",
            )
        })?;
        set_private_directory(root.path())?;
        let destination = root.path().join("semantic");
        let projection_destination = root.path().join("projection");
        let source = source.to_path_buf();
        let projection_source = projection_source.to_path_buf();
        let copy = destination.clone();
        let projection_copy = projection_destination.clone();
        tokio::task::spawn_blocking(move || {
            copy_private_tree(&source, &copy)?;
            copy_private_tree(&projection_source, &projection_copy)
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "graph snapshot copy task failed"))??;

        let semantic = Arc::new(FlureeSemanticLedger::open_file(&destination, options).await?);
        let copied = semantic.capture_current(None).await?;
        let projection = Arc::new(
            RedbProjection::open(
                &projection_destination,
                projection_binding,
                GenerationOptions::default(),
            )
            .await?,
        );
        // Do not start a coordinator to repair a lagging copy. The read adapter
        // must open `copied.snapshot()` exactly and fail if that generation was
        // not already present; substituting a stale generation is forbidden.
        let after = original.capture_current(None).await?;
        if before != after || copied != before {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "Semantic source changed during extract-only graph snapshot",
            ));
        }
        Ok(Self {
            _root: root,
            semantic,
            projection,
            capture: copied,
        })
    }

    pub(crate) fn semantic(&self) -> &Arc<FlureeSemanticLedger> {
        &self.semantic
    }

    pub(crate) fn projection(&self) -> &Arc<RedbProjection> {
        &self.projection
    }

    pub(crate) fn capture(&self) -> &SemanticCapture {
        &self.capture
    }
}

/// Fail-closed composition around an isolated read snapshot.
///
/// Every disclosure-producing operation rechecks original current authority
/// both before execution and after the result is staged. A failed check closes
/// the composition permanently, ensuring a caller cannot continue with cached
/// results after revocation.
pub(crate) struct ExtractOnlyGraphRead {
    snapshot: Arc<IsolatedGraphReadSnapshot>,
    authority: Arc<dyn CurrentGraphReadAuthority>,
    closed: AtomicBool,
}

impl ExtractOnlyGraphRead {
    pub(crate) fn new(
        snapshot: IsolatedGraphReadSnapshot,
        authority: Arc<dyn CurrentGraphReadAuthority>,
    ) -> Arc<Self> {
        Arc::new(Self {
            snapshot: Arc::new(snapshot),
            authority,
            closed: AtomicBool::new(false),
        })
    }

    pub(crate) fn snapshot(&self) -> &IsolatedGraphReadSnapshot {
        &self.snapshot
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    pub(crate) async fn execute<T, F, Fut>(&self, operation: F) -> Result<T>
    where
        F: FnOnce(Arc<FlureeSemanticLedger>, Arc<RedbProjection>, SemanticCapture) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        if let Err(error) = self.authority.reauthorize().await {
            self.close();
            return Err(error);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }

        let staged = operation(
            self.snapshot.semantic.clone(),
            self.snapshot.projection.clone(),
            self.snapshot.capture.clone(),
        )
        .await?;

        if let Err(error) = self.authority.reauthorize().await {
            self.close();
            return Err(error);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        Ok(staged)
    }
}

fn closed_error() -> Error {
    Error::new(
        ErrorKind::Denied,
        "extract-only graph read composition unavailable",
    )
}

fn set_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
            Error::new(
                ErrorKind::Backend,
                "extract-only graph snapshot unavailable",
            )
        })?;
    }
    Ok(())
}

fn copy_private_tree(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|_| Error::new(ErrorKind::Backend, "Semantic copy source unavailable"))?;
    if metadata.file_type().is_symlink() {
        return Err(Error::new(ErrorKind::Denied, "unsafe Semantic copy source"));
    }
    if metadata.is_file() {
        let parent = destination
            .parent()
            .ok_or_else(|| Error::invalid("Semantic copy destination"))?;
        fs::create_dir_all(parent)
            .map_err(|_| Error::new(ErrorKind::Backend, "Semantic copy failed"))?;
        fs::copy(source, destination)
            .map_err(|_| Error::new(ErrorKind::Backend, "Semantic copy failed"))?;
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(Error::new(ErrorKind::Denied, "unsafe Semantic copy source"));
    }
    fs::create_dir_all(destination)
        .map_err(|_| Error::new(ErrorKind::Backend, "Semantic copy failed"))?;
    for entry in
        fs::read_dir(source).map_err(|_| Error::new(ErrorKind::Backend, "Semantic copy failed"))?
    {
        let entry = entry.map_err(|_| Error::new(ErrorKind::Backend, "Semantic copy failed"))?;
        copy_private_tree(&entry.path(), &destination.join(entry.file_name()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        acquisition::{AcquisitionService, AdmissionContext, WaitPoint},
        graph_query::GraphQueryLimits,
        Service,
    };
    use cdb_core::{
        artifact::ArtifactRef,
        id::{AttemptId, BundleId, ContentHash, ExtractionRunId, Iri, JobId, VersionId},
        semantic_admission::{stable_acquisition_v2_claim_id, ValidatedSemanticBundle},
        CanonicalValue as V, Limits, Timestamp,
    };
    use std::{
        collections::BTreeSet,
        sync::atomic::{AtomicUsize, Ordering},
    };

    fn projection_binding(capture: &SemanticCapture) -> ProjectionCheckpoint {
        ProjectionCheckpoint::new(
            capture.snapshot().clone(),
            VersionId::new("ctxql-semantic-rdf/v1").unwrap(),
            VersionId::new("live").unwrap(),
            Iri::new("urn:ctxql:semantic-projection:v1").unwrap(),
        )
        .unwrap()
    }

    fn semantic_claim(
        component: &str,
        subject: &str,
        predicate: &str,
        lexical: &str,
    ) -> cdb_core::claim::CandidateClaim {
        let mut value = V::parse(
            br#"{"claim_id":"urn:ctxql:claim:v2:placeholder","claim_type":"urn:type:claim","confidence":1,"ext":{"ctxql.acquisition.v2/claim_identity":"stable-component/v1","ctxql.acquisition.v2/component_ref":"placeholder"},"grounding_level":"source_lineage_available","lineage":{"schema":"ctxql.lineage.v1","sources":[{"source_id":"urn:source:name-regression","kind":"document","uri":"urn:evidence:name-regression"}]},"object_id":{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#string","value":"placeholder","language":null},"object_type":"http://www.w3.org/2001/XMLSchema#string","relation":"urn:predicate:placeholder","relation_type":"urn:type:relation","subject_id":"urn:subject:placeholder","subject_type":"urn:type:entity"}"#,
            Limits::default(),
        )
        .unwrap();
        {
            let V::Object(fields) = &mut value else {
                unreachable!()
            };
            fields.insert("subject_id".into(), V::string(subject));
            fields.insert("relation".into(), V::string(predicate));
            let V::Object(object) = fields.get_mut("object_id").unwrap() else {
                unreachable!()
            };
            object.insert("value".into(), V::string(lexical));
            let V::Object(ext) = fields.get_mut("ext").unwrap() else {
                unreachable!()
            };
            ext.insert(
                "ctxql.acquisition.v2/component_ref".into(),
                V::string(component),
            );
        }
        let provisional = cdb_core::claim::CandidateClaim::from_value(&value).unwrap();
        let id = stable_acquisition_v2_claim_id(&provisional, Limits::default()).unwrap();
        let V::Object(fields) = &mut value else {
            unreachable!()
        };
        fields.insert("claim_id".into(), V::string(id.as_str()));
        cdb_core::claim::CandidateClaim::from_value(&value).unwrap()
    }

    async fn publish_graph_config(
        fixture: &crate::acquisition_v2_fixture::AcquisitionV2Fixture,
    ) -> ArtifactRef {
        let bytes = include_str!("../../../fixtures/conformance/graph-workspace/config.json");
        let hash = ContentHash::of_bytes(bytes.as_bytes());
        let reference = ArtifactRef::new(
            Iri::new("https://test/semantic-name-landing-config").unwrap(),
            VersionId::new("1").unwrap(),
            hash.clone(),
        );
        let token = fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
        let publisher = Service::open(fixture.config().unwrap()).await.unwrap();
        publisher
            .dispatch(
                &token,
                &serde_json::to_vec(&serde_json::json!({
                    "schema": "ctxql-service/v1",
                    "op": "publish",
                    "artifact": {
                        "iri": reference.iri().as_str(),
                        "version": reference.version().as_str(),
                        "hash": hash.as_str()
                    },
                    "content": bytes
                }))
                .unwrap(),
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
        publisher.shutdown().await.unwrap();
        reference
    }

    struct CountingAuthority {
        checks: AtomicUsize,
        deny_at: usize,
    }

    impl CurrentGraphReadAuthority for CountingAuthority {
        fn reauthorize(&self) -> IoFuture<'_, ()> {
            Box::pin(async move {
                let check = self.checks.fetch_add(1, Ordering::SeqCst) + 1;
                if check >= self.deny_at {
                    Err(Error::new(ErrorKind::Denied, "current authority denied"))
                } else {
                    Ok(())
                }
            })
        }
    }

    #[tokio::test]
    async fn isolated_snapshot_matches_source_without_advancing_it() {
        let fixture = crate::acquisition_v2_fixture::AcquisitionV2Fixture::create()
            .await
            .unwrap();
        let config = fixture.config().unwrap();
        let (path, options) = config.semantic_binding().unwrap();
        let original = FlureeSemanticLedger::open_file(path, options.clone())
            .await
            .unwrap();
        let before = original.capture_current(None).await.unwrap();

        let isolated = IsolatedGraphReadSnapshot::copy_from(
            &original,
            path,
            options,
            &config.projection,
            projection_binding(&before),
        )
        .await
        .unwrap();

        assert_eq!(isolated.capture(), &before);
        assert!(isolated.projection().cached_snapshots().await.is_ok());
        assert_eq!(
            isolated.semantic().capture_current(None).await.unwrap(),
            before
        );
        assert_eq!(original.capture_current(None).await.unwrap(), before);
    }

    #[tokio::test]
    async fn native_graph_query_lands_exact_and_supported_names_with_large_catalog() {
        const LABEL: &str = "http://www.w3.org/2000/01/rdf-schema#label";
        const ALT_LABEL: &str = "http://www.w3.org/2004/02/skos/core#altLabel";
        const COMMONS_NAME: &str = "https://www.omg.org/spec/Commons/Designators/hasTextualName";

        let fixture = crate::acquisition_v2_fixture::AcquisitionV2Fixture::create()
            .await
            .unwrap();
        let config = publish_graph_config(&fixture).await;
        let acquisition = AcquisitionService::open(
            &fixture.config().unwrap(),
            fixture.catalog_identity().clone(),
        )
        .await
        .unwrap();
        let mut claims = vec![
            semantic_claim(
                "window:name#entity:a-label",
                "urn:opaque:7f2a",
                COMMONS_NAME,
                "Northstar Background Holdings",
            ),
            semantic_claim(
                "window:name#entity:a-alt-label",
                "urn:opaque:7f2a",
                ALT_LABEL,
                "Northstar Background",
            ),
            semantic_claim(
                "window:name#entity:b-label",
                "urn:opaque:9c41",
                LABEL,
                "Northstar Background Holdings",
            ),
            semantic_claim(
                "window:name#entity:non-label-text",
                "urn:opaque:text-only",
                "urn:predicate:description",
                "Northstar Background Holdings",
            ),
        ];
        let label_supports = claims[..3]
            .iter()
            .map(|claim| claim.id().as_str().to_owned())
            .collect::<BTreeSet<_>>();
        let exact_label_supports = claims[..2]
            .iter()
            .map(|claim| claim.id().as_str().to_owned())
            .collect::<BTreeSet<_>>();
        // Each named filler contributes an identifier and lexical entry, making
        // the authorized landing catalog larger than the 214-record output-derived
        // execution budget that previously rejected even exact queries.
        claims.extend((0..110).map(|index| {
            semantic_claim(
                &format!("window:name#filler:{index}"),
                &format!("urn:opaque:filler:{index}"),
                COMMONS_NAME,
                &format!("Catalog filler {index}"),
            )
        }));
        let capture = acquisition
            .semantic_writer
            .session()
            .await
            .capture_current()
            .await
            .unwrap();
        let bundle = ValidatedSemanticBundle::new(
            BundleId::new("bundle:semantic-name-landing").unwrap(),
            ExtractionRunId::new("extraction:semantic-name-landing").unwrap(),
            capture,
            V::object([
                (
                    "schema".into(),
                    V::string("ctxql-extraction-admission-descriptor/v2"),
                ),
                (
                    "evaluation_id".into(),
                    V::string("evaluation:semantic-name-landing"),
                ),
                (
                    "review_payload_root".into(),
                    V::string(ContentHash::of_bytes(b"semantic name landing").as_str()),
                ),
                ("ontology_mode".into(), V::string("direct")),
            ])
            .unwrap(),
            claims
                .into_iter()
                .enumerate()
                .map(|(index, claim)| (format!("v2:name:{index}"), claim))
                .collect(),
            Limits::default(),
        )
        .unwrap();
        acquisition
            .admit_foreground(
                JobId::new("job:semantic-name-landing").unwrap(),
                AttemptId::new("attempt:semantic-name-landing").unwrap(),
                &bundle,
                ContentHash::of_bytes(b"semantic name landing selectors"),
                V::object([]).unwrap(),
                Timestamp::from_millis(1).unwrap(),
                WaitPoint::Projected,
                AdmissionContext::NoGraph,
            )
            .await
            .unwrap();

        let host = acquisition
            .graph_query_host(config, None, GraphQueryLimits::default())
            .await
            .unwrap();
        let query = |name: &str| {
            serde_json::to_vec(&serde_json::json!({
                "about": [{"from": [name], "match": "approximate"}],
                // Alias supports must survive even when not returned as edges.
                "walk": {"direction":"outgoing", "predicates":[["meta:relation","!=",ALT_LABEL]]},
                "bounds": {
                    "max_depth": 1,
                    "seed_limit": 8,
                    "fanout_limit": 8,
                    "max_claims": 32,
                    "path_limit": 16
                }
            }))
            .unwrap()
        };
        for name in ["Northstar Background Holdings", "Background"] {
            let result = host
                .query(
                    "test-issuer",
                    "test-session",
                    &query(name),
                    Arc::new(AtomicBool::new(false)),
                    GraphQueryLimits::default(),
                )
                .await
                .unwrap()
                .unwrap();
            let ids = result
                .graph
                .nodes
                .iter()
                .map(|node| node.canonical_iri.as_str())
                .collect::<BTreeSet<_>>();
            assert!(ids.contains("urn:opaque:7f2a"), "{name}: {ids:?}");
            assert!(ids.contains("urn:opaque:9c41"), "{name}: {ids:?}");
            assert!(!ids.contains("urn:opaque:text-only"), "{name}: {ids:?}");
            assert_eq!(
                ids.iter()
                    .filter(|id| matches!(**id, "urn:opaque:7f2a" | "urn:opaque:9c41"))
                    .count(),
                2,
                "equal labels must retain two canonical identities"
            );
            let dependencies = result
                .graph
                .claims
                .iter()
                .flat_map(|claim| claim.dependencies.iter().cloned())
                .collect::<BTreeSet<_>>();
            assert!(dependencies.iter().any(|id| label_supports.contains(id)));
            assert!(result
                .graph
                .claims
                .iter()
                .all(|claim| matches!(claim.predicate.as_str(), LABEL | COMMONS_NAME)));
            assert!(label_supports.is_subset(&result.dependencies));
            let node_supports = result
                .graph
                .nodes
                .iter()
                .flat_map(|node| node.dependencies.iter().cloned())
                .collect::<BTreeSet<_>>();
            assert!(label_supports.is_subset(&node_supports));
        }

        let exact = serde_json::to_vec(&serde_json::json!({
            "about": [{"from": ["urn:opaque:7f2a"], "match": "exact"}],
            "walk": {"direction":"outgoing"},
            "bounds": {
                "max_depth": 1,
                "seed_limit": 1,
                "fanout_limit": 8,
                "max_claims": 8,
                "path_limit": 8
            }
        }))
        .unwrap();
        let exact = host
            .query(
                "test-issuer",
                "test-session",
                &exact,
                Arc::new(AtomicBool::new(false)),
                GraphQueryLimits::default(),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(exact
            .graph
            .nodes
            .iter()
            .any(|node| node.canonical_iri == "urn:opaque:7f2a"));
        assert!(exact_label_supports.is_subset(&exact.dependencies));
        acquisition.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn post_execution_revocation_suppresses_result_and_closes_composition() {
        let fixture = crate::acquisition_v2_fixture::AcquisitionV2Fixture::create()
            .await
            .unwrap();
        let config = fixture.config().unwrap();
        let (path, options) = config.semantic_binding().unwrap();
        let original = FlureeSemanticLedger::open_file(path, options.clone())
            .await
            .unwrap();
        let capture = original.capture_current(None).await.unwrap();
        let isolated = IsolatedGraphReadSnapshot::copy_from(
            &original,
            path,
            options,
            &config.projection,
            projection_binding(&capture),
        )
        .await
        .unwrap();
        let authority = Arc::new(CountingAuthority {
            checks: AtomicUsize::new(0),
            deny_at: 2,
        });
        let composition = ExtractOnlyGraphRead::new(isolated, authority.clone());

        let error = composition
            .execute(|_, _, _| async { Ok("must not be disclosed") })
            .await
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Denied);
        assert_eq!(authority.checks.load(Ordering::SeqCst), 2);

        let error = composition
            .execute(|_, _, _| async { Ok("must not run") })
            .await
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Denied);
        assert_eq!(authority.checks.load(Ordering::SeqCst), 2);
    }

    #[cfg(unix)]
    #[test]
    fn private_copy_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        fs::write(source.path().join("target"), b"private").unwrap();
        symlink(source.path().join("target"), source.path().join("link")).unwrap();

        let error = copy_private_tree(source.path(), &destination.path().join("copy")).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Denied);
    }
}
