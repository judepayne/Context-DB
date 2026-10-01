use cdb_core::{admission::*, contracts::*, id::*, snapshot::*, Limits};
use cdb_projection_redb::{GenerationOptions, RedbProjection};
fn pin(r: &str) -> SnapshotRef {
    SnapshotRef::new(
        BackendId::new("test").unwrap(),
        GraphPin::new(
            AuthorityId::new("test:authority").unwrap(),
            GraphId::new("g").unwrap(),
            VersionId::new(r).unwrap(),
            ResourceId::new(format!("receipt:{r}")).unwrap(),
        ),
    )
}
fn cp(r: &str) -> ProjectionCheckpoint {
    checkpoint(r, "live")
}
fn semantic_pin(r: &str) -> SnapshotRef {
    semantic_pin_with_receipt(r, &format!("cid:{r}"))
}
fn semantic_pin_with_receipt(r: &str, receipt: &str) -> SnapshotRef {
    SnapshotRef::new(
        BackendId::new("fluree:semantic").unwrap(),
        GraphPin::new(
            AuthorityId::new("semantic:authority").unwrap(),
            GraphId::new("semantic:ledger").unwrap(),
            VersionId::new(r).unwrap(),
            ResourceId::new(receipt).unwrap(),
        ),
    )
}
fn semantic_checkpoint(r: &str, receipt: &str, generation: &str) -> ProjectionCheckpoint {
    ProjectionCheckpoint::new(
        semantic_pin_with_receipt(r, receipt),
        VersionId::new("ctxql-semantic-rdf/v1").unwrap(),
        VersionId::new(generation).unwrap(),
        Iri::new("urn:ctxql:semantic-projection:v1").unwrap(),
    )
    .unwrap()
}
fn semantic_cp(r: &str) -> ProjectionCheckpoint {
    semantic_checkpoint(r, &format!("cid:{r}"), "live")
}
fn checkpoint(r: &str, g: &str) -> ProjectionCheckpoint {
    ProjectionCheckpoint::new(
        pin(r),
        VersionId::new("ctxql-projection/v1").unwrap(),
        VersionId::new(g).unwrap(),
        Iri::new("urn:raw").unwrap(),
    )
    .unwrap()
}
fn record(id: &str) -> ExportRecord {
    ExportRecord::Resource(
        DependencyRecord::new(
            "ctxql-resource/v1",
            ResourceId::new(id).unwrap(),
            ResourceKind::Identity,
            vec![Fact::new(
                Iri::new("urn:fact").unwrap(),
                FactTerm::Reference(ResourceId::new("target").unwrap()),
            )],
        )
        .unwrap(),
    )
}
fn export(r: &str, rs: Vec<ExportRecord>) -> CompleteExport {
    export_for(pin(r), rs)
}
fn semantic_export(r: &str, receipt: &str, rs: Vec<ExportRecord>) -> CompleteExport {
    export_for(semantic_pin_with_receipt(r, receipt), rs)
}
fn export_for(pin: SnapshotRef, rs: Vec<ExportRecord>) -> CompleteExport {
    CompleteExport::collect(
        pin.clone(),
        ResourceId::new("export").unwrap(),
        vec![Page::new(rs, pin, None, PageSize::new(100).unwrap()).unwrap()],
        100,
    )
    .unwrap()
}
fn batch(a: &str, b: &str, records: Vec<ExportRecord>) -> ChangeBatch {
    ChangeBatch::new(
        "ctxql-change/v1",
        pin(a),
        pin(b),
        records
            .into_iter()
            .map(|r| match r {
                ExportRecord::Resource(r) => RecordChange::Resource(ResourceChange::Add(r)),
                _ => unreachable!(),
            })
            .collect(),
        Limits::default(),
    )
    .unwrap()
}
fn run(f: impl std::future::Future<Output = ()>) {
    tokio::runtime::Runtime::new().unwrap().block_on(f);
}
#[test]
fn initial_reopen_discovers_kernel_checkpoint_and_lock() {
    run(async {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("projection");
        let o = GenerationOptions::default();
        let s = RedbProjection::create(&p, cp("0"), o).await.unwrap();
        assert!(s.checkpoint().await.unwrap().is_none());
        assert!(RedbProjection::create(&p, cp("0"), o).await.is_err());
        assert!(RedbProjection::open(&p, cp("0"), o).await.is_err());
        s.build(&export("0", vec![record("a")]), &cp("0"))
            .await
            .unwrap();
        s.apply(&batch("0", "1", vec![record("b")]), &cp("1"))
            .await
            .unwrap();
        drop(s);
        let s = RedbProjection::open(&p, cp("0"), o).await.unwrap();
        assert_eq!(s.checkpoint().await.unwrap(), Some(cp("1")));
        assert_eq!(
            s.open_generation(&pin("1"))
                .await
                .unwrap()
                .scan(PageSize::new(10).unwrap(), None)
                .unwrap()
                .items()
                .len(),
            2
        );
    });
}
#[test]
fn held_old_view_survives_apply_and_owner_drop() {
    run(async {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("projection");
        let o = GenerationOptions::default();
        let s = RedbProjection::create(&p, cp("0"), o).await.unwrap();
        s.build(&export("0", vec![record("a")]), &cp("0"))
            .await
            .unwrap();
        let old = s.open_generation(&pin("0")).await.unwrap();
        s.apply(&batch("0", "1", vec![record("b")]), &cp("1"))
            .await
            .unwrap();
        assert!(s.open_generation(&pin("0")).await.is_err());
        drop(s);
        assert!(old
            .resource(&ResourceId::new("b").unwrap())
            .unwrap()
            .is_none());
        assert!(RedbProjection::open(&p, cp("0"), o).await.is_err());
        drop(old);
        assert!(RedbProjection::open(&p, cp("0"), o).await.is_ok());
    });
}
#[test]
fn historical_build_never_moves_live_and_reopens() {
    run(async {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("projection");
        let o = GenerationOptions::default();
        let s = RedbProjection::create(&p, cp("2"), o).await.unwrap();
        s.build(&export("2", vec![record("a"), record("b")]), &cp("2"))
            .await
            .unwrap();
        s.build(&export("1", vec![record("a")]), &checkpoint("1", "history"))
            .await
            .unwrap();
        assert_eq!(s.checkpoint().await.unwrap(), Some(cp("2")));
        drop(s);
        let s = RedbProjection::open(&p, cp("0"), o).await.unwrap();
        assert_eq!(s.cached_snapshots().await.unwrap().len(), 2);
        assert_eq!(
            s.open_generation(&pin("1"))
                .await
                .unwrap()
                .scan(PageSize::new(10).unwrap(), None)
                .unwrap()
                .items()
                .len(),
            1
        );
    });
}
#[test]
fn ahead_cache_equal_different_generation_allows_apply() {
    run(async {
        let d = tempfile::tempdir().unwrap();
        let s = RedbProjection::create(
            d.path().join("projection"),
            cp("0"),
            GenerationOptions::default(),
        )
        .await
        .unwrap();
        s.build(&export("0", vec![record("a")]), &cp("0"))
            .await
            .unwrap();
        s.build(
            &export("1", vec![record("b"), record("a")]),
            &checkpoint("1", "cache"),
        )
        .await
        .unwrap();
        s.apply(&batch("0", "1", vec![record("b")]), &cp("1"))
            .await
            .unwrap();
        assert_eq!(s.checkpoint().await.unwrap(), Some(cp("1")));
    });
}
#[test]
fn ahead_mismatch_and_bad_predecessor_leave_live_unchanged() {
    run(async {
        let d = tempfile::tempdir().unwrap();
        let s = RedbProjection::create(
            d.path().join("projection"),
            cp("0"),
            GenerationOptions::default(),
        )
        .await
        .unwrap();
        s.build(&export("0", vec![record("a")]), &cp("0"))
            .await
            .unwrap();
        s.build(
            &export("1", vec![record("wrong")]),
            &checkpoint("1", "cache"),
        )
        .await
        .unwrap();
        assert!(s
            .apply(&batch("0", "1", vec![record("b")]), &cp("1"))
            .await
            .is_err());
        assert_eq!(s.checkpoint().await.unwrap(), Some(cp("0")));
        assert!(s
            .open_generation(&pin("0"))
            .await
            .unwrap()
            .resource(&ResourceId::new("b").unwrap())
            .unwrap()
            .is_none());
        assert!(s.apply(&batch("gap", "2", vec![]), &cp("2")).await.is_err());
    });
}
#[test]
fn fault_before_publish_reopen_and_explicit_rebuild_preserve_readers() {
    run(async {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("projection");
        let o = GenerationOptions::default();
        let s = RedbProjection::create(&p, cp("0"), o).await.unwrap();
        s.set_before_publish_fault(true);
        assert!(s.build(&export("0", vec![]), &cp("0")).await.is_err());
        assert!(s.checkpoint().await.unwrap().is_none());
        s.set_before_publish_fault(false);
        s.build(&export("0", vec![record("a")]), &cp("0"))
            .await
            .unwrap();
        let old = s.open_generation(&pin("0")).await.unwrap();
        s.set_before_publish_fault(true);
        assert!(s
            .rebuild_live(
                &export("1", vec![record("b")]),
                &checkpoint("1", "replacement")
            )
            .await
            .is_err());
        assert_eq!(s.checkpoint().await.unwrap(), Some(cp("0")));
        s.set_before_publish_fault(false);
        s.rebuild_live(
            &export("1", vec![record("b")]),
            &checkpoint("1", "replacement"),
        )
        .await
        .unwrap();
        assert!(old
            .resource(&ResourceId::new("a").unwrap())
            .unwrap()
            .is_some());
        assert!(s.evict(&pin("0")).await.is_err());
        drop(old);
        s.evict(&pin("0")).await.unwrap();
        drop(s);
        let s = RedbProjection::open(&p, cp("0"), o).await.unwrap();
        assert_eq!(
            s.checkpoint().await.unwrap(),
            Some(checkpoint("1", "replacement"))
        );
    });
}
#[test]
fn latest_existing_reopens_at_each_active_generation() {
    run(async {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("projection");
        let o = GenerationOptions::default();
        let s = RedbProjection::create(&p, cp("0"), o).await.unwrap();
        s.build(&export("0", vec![record("a")]), &cp("0"))
            .await
            .unwrap();
        drop(s);

        let first = RedbProjection::open_latest_existing(&p, cp("0"), o)
            .await
            .unwrap();
        assert_eq!(first.identity(), &pin("0"));
        assert!(first
            .resource(&ResourceId::new("a").unwrap())
            .unwrap()
            .is_some());
        drop(first);

        let s = RedbProjection::open(&p, cp("0"), o).await.unwrap();
        s.apply(&batch("0", "1", vec![record("b")]), &cp("1"))
            .await
            .unwrap();
        drop(s);

        let second = RedbProjection::open_latest_existing(&p, cp("0"), o)
            .await
            .unwrap();
        assert_eq!(second.identity(), &pin("1"));
        assert!(second
            .resource(&ResourceId::new("b").unwrap())
            .unwrap()
            .is_some());
    });
}
#[test]
fn latest_semantic_existing_chooses_completed_cache_ahead_of_active() {
    run(async {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("projection");
        let o = GenerationOptions {
            max_generations: 9,
            ..Default::default()
        };
        let s = RedbProjection::create(&p, semantic_cp("10"), o)
            .await
            .unwrap();
        s.build(
            &semantic_export("10", "cid:10", vec![record("at-10")]),
            &semantic_cp("10"),
        )
        .await
        .unwrap();
        for revision in 11..=18 {
            let revision = revision.to_string();
            let receipt = format!("cid:{revision}");
            s.build(
                &semantic_export(&revision, &receipt, vec![record(&format!("at-{revision}"))]),
                &semantic_checkpoint(&revision, &receipt, "cache"),
            )
            .await
            .unwrap();
        }
        assert_eq!(
            s.checkpoint().await.unwrap().unwrap().snapshot(),
            &semantic_pin("10")
        );
        drop(s);

        let active = RedbProjection::open_latest_existing(&p, semantic_cp("10"), o)
            .await
            .unwrap();
        assert_eq!(active.identity(), &semantic_pin("10"));
        drop(active);

        let latest = RedbProjection::open_latest_semantic_existing(&p, semantic_cp("10"), o)
            .await
            .unwrap();
        assert_eq!(latest.identity(), &semantic_pin("18"));
        assert!(latest
            .resource(&ResourceId::new("at-18").unwrap())
            .unwrap()
            .is_some());
        assert!(latest
            .resource(&ResourceId::new("at-10").unwrap())
            .unwrap()
            .is_none());
        assert!(RedbProjection::open(&p, semantic_cp("10"), o)
            .await
            .is_err());
        assert_eq!(
            latest
                .scan(PageSize::new(10).unwrap(), None)
                .unwrap()
                .items()
                .len(),
            1
        );
    });
}
#[test]
fn latest_semantic_existing_rejects_non_semantic_and_wrong_algorithm() {
    run(async {
        let d = tempfile::tempdir().unwrap();
        let o = GenerationOptions::default();
        let generic_path = d.path().join("generic");
        let generic = RedbProjection::create(&generic_path, cp("1"), o)
            .await
            .unwrap();
        generic.build(&export("1", vec![]), &cp("1")).await.unwrap();
        drop(generic);
        assert!(
            RedbProjection::open_latest_semantic_existing(&generic_path, cp("1"), o)
                .await
                .is_err()
        );

        let wrong_path = d.path().join("wrong-algorithm");
        let wrong = ProjectionCheckpoint::new(
            semantic_pin("1"),
            VersionId::new("ctxql-semantic-rdf/v1").unwrap(),
            VersionId::new("live").unwrap(),
            Iri::new("urn:wrong").unwrap(),
        )
        .unwrap();
        let store = RedbProjection::create(&wrong_path, wrong.clone(), o)
            .await
            .unwrap();
        store
            .build(&semantic_export("1", "cid:1", vec![]), &wrong)
            .await
            .unwrap();
        drop(store);
        assert!(
            RedbProjection::open_latest_semantic_existing(&wrong_path, wrong, o)
                .await
                .is_err()
        );

        let semantic_path = d.path().join("semantic");
        let semantic = semantic_cp("1");
        let store = RedbProjection::create(&semantic_path, semantic.clone(), o)
            .await
            .unwrap();
        store
            .build(&semantic_export("1", "cid:1", vec![]), &semantic)
            .await
            .unwrap();
        drop(store);
        let foreign = ProjectionCheckpoint::new(
            SnapshotRef::new(
                BackendId::new("fluree:semantic").unwrap(),
                GraphPin::new(
                    AuthorityId::new("foreign:authority").unwrap(),
                    GraphId::new("semantic:ledger").unwrap(),
                    VersionId::new("1").unwrap(),
                    ResourceId::new("cid:1").unwrap(),
                ),
            ),
            VersionId::new("ctxql-semantic-rdf/v1").unwrap(),
            VersionId::new("live").unwrap(),
            Iri::new("urn:ctxql:semantic-projection:v1").unwrap(),
        )
        .unwrap();
        assert!(
            RedbProjection::open_latest_semantic_existing(&semantic_path, foreign, o)
                .await
                .is_err()
        );
    });
}
#[test]
fn latest_semantic_existing_rejects_invalid_revision_and_ambiguous_highest_receipt() {
    run(async {
        let d = tempfile::tempdir().unwrap();
        let o = GenerationOptions::default();
        for revision in ["0", "latest", "018"] {
            let p = d.path().join(format!("invalid-{revision}"));
            let checkpoint = semantic_checkpoint(revision, "cid:invalid", "live");
            let store = RedbProjection::create(&p, checkpoint.clone(), o)
                .await
                .unwrap();
            store
                .build(
                    &semantic_export(revision, "cid:invalid", vec![]),
                    &checkpoint,
                )
                .await
                .unwrap();
            drop(store);
            assert!(
                RedbProjection::open_latest_semantic_existing(&p, checkpoint, o)
                    .await
                    .is_err()
            );
        }

        let p = d.path().join("ambiguous");
        let binding = semantic_cp("10");
        let store = RedbProjection::create(&p, binding.clone(), o)
            .await
            .unwrap();
        store
            .build(&semantic_export("10", "cid:10", vec![]), &binding)
            .await
            .unwrap();
        for receipt in ["cid:18-a", "cid:18-b"] {
            store
                .build(
                    &semantic_export("18", receipt, vec![]),
                    &semantic_checkpoint("18", receipt, "cache"),
                )
                .await
                .unwrap();
        }
        drop(store);
        assert!(
            RedbProjection::open_latest_semantic_existing(&p, binding, o)
                .await
                .is_err()
        );
    });
}
#[test]
fn latest_existing_rejects_missing_busy_and_foreign_stores() {
    run(async {
        let d = tempfile::tempdir().unwrap();
        let missing = d.path().join("missing");
        let o = GenerationOptions::default();
        assert!(RedbProjection::open_latest_existing(&missing, cp("0"), o)
            .await
            .is_err());

        let p = d.path().join("projection");
        let s = RedbProjection::create(&p, cp("0"), o).await.unwrap();
        s.build(&export("0", vec![]), &cp("0")).await.unwrap();
        assert!(RedbProjection::open_latest_existing(&p, cp("0"), o)
            .await
            .is_err());
        drop(s);

        let foreign = ProjectionCheckpoint::new(
            pin("0"),
            VersionId::new("ctxql-projection/v1").unwrap(),
            VersionId::new("live").unwrap(),
            Iri::new("urn:foreign").unwrap(),
        )
        .unwrap();
        assert!(RedbProjection::open_latest_existing(&p, foreign, o)
            .await
            .is_err());
    });
}
#[test]
fn latest_existing_does_not_clean_reserved_staging_files() {
    run(async {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("projection");
        let o = GenerationOptions::default();
        let s = RedbProjection::create(&p, cp("0"), o).await.unwrap();
        s.set_before_publish_fault(true);
        assert!(s.build(&export("0", vec![]), &cp("0")).await.is_err());
        drop(s);

        let orphan = p.join("generation-0.redb");
        std::fs::write(&orphan, b"reserved staging sentinel").unwrap();
        assert!(RedbProjection::open_latest_existing(&p, cp("0"), o)
            .await
            .is_err());
        assert_eq!(
            std::fs::read(&orphan).unwrap(),
            b"reserved staging sentinel"
        );

        let owner = RedbProjection::open(&p, cp("0"), o).await.unwrap();
        assert!(!orphan.exists());
        drop(owner);
    });
}
#[test]
fn bounded_eviction_and_foreign_files_are_safe() {
    run(async {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("projection");
        let o = GenerationOptions {
            max_generations: 2,
            ..Default::default()
        };
        let s = RedbProjection::create(&p, cp("0"), o).await.unwrap();
        std::fs::write(p.join("authority.data"), b"untouched").unwrap();
        s.build(&export("0", vec![]), &cp("0")).await.unwrap();
        s.build(&export("1", vec![]), &checkpoint("1", "cache"))
            .await
            .unwrap();
        let held = s.open_generation(&pin("1")).await.unwrap();
        assert!(s.build(&export("2", vec![]), &cp("2")).await.is_err());
        assert!(s.evict(&pin("1")).await.is_err());
        drop(held);
        s.evict(&pin("1")).await.unwrap();
        s.build(&export("2", vec![]), &cp("2")).await.unwrap();
        assert!(s.evict(&pin("0")).await.is_err());
        drop(s);
        assert_eq!(
            std::fs::read(p.join("authority.data")).unwrap(),
            b"untouched"
        );
        let foreign = ProjectionCheckpoint::new(
            pin("0"),
            VersionId::new("ctxql-projection/v1").unwrap(),
            VersionId::new("live").unwrap(),
            Iri::new("urn:foreign").unwrap(),
        )
        .unwrap();
        assert!(RedbProjection::open(&p, foreign, o).await.is_err());
        assert!(RedbProjection::open(&p, cp("0"), o).await.is_ok());
    });
}
