//! Real process kills at acknowledged storage barriers; not power-loss certification.
mod common_p3;
use cdb_backend_fluree::{AuthorityOptions, FlureeBackend};
use cdb_core::{
    admission::*,
    contracts::*,
    id::*,
    record_codec::{snapshot_from_value, snapshot_value},
    snapshot::*,
    CanonicalValue as V, Limits,
};
use cdb_projection_redb::{Coordinator, CoordinatorOptions, GenerationOptions, RedbProjection};
use std::{
    io::{BufRead, Write},
    path::Path,
    sync::Arc,
    time::Duration,
};
fn options(root: &Path) -> AuthorityOptions {
    AuthorityOptions::new(
        root.join("authority"),
        "recovery:main".into(),
        BackendId::new("fluree").unwrap(),
        AuthorityId::new("process-authority").unwrap(),
        GraphId::new("graph").unwrap(),
    )
}
fn checkpoint(pin: SnapshotRef) -> ProjectionCheckpoint {
    ProjectionCheckpoint::new(
        pin,
        VersionId::new("ctxql-projection/v1").unwrap(),
        VersionId::new("recovery").unwrap(),
        Iri::new("urn:ctxql:raw:v1").unwrap(),
    )
    .unwrap()
}
fn edge_batch(id: &str) -> AdmissionBatch {
    let mut b = cdb_testkit::reference_fixture::FixtureBuilder::new();
    b.edge(
        id,
        "s",
        cdb_core::claim::ClaimObject::Entity(EntityId::new("o").unwrap()),
        "1",
    )
    .unwrap();
    b.into_batch().unwrap()
}
fn batch() -> AdmissionBatch {
    AdmissionBatch::new(
        edge_batch("new-edge").claims().to_vec(),
        vec![],
        vec![ResourceChange::Add(
            DependencyRecord::new(
                "ctxql-resource/v1",
                ResourceId::new("persisted").unwrap(),
                ResourceKind::Ontology,
                vec![Fact::new(
                    Iri::new("urn:fact").unwrap(),
                    FactTerm::Reference(ResourceId::new("value:日本語").unwrap()),
                )],
            )
            .unwrap(),
        )],
        vec![],
        V::Object(Default::default()),
        Limits::default(),
    )
    .unwrap()
}
async fn export(b: &FlureeBackend, pin: &SnapshotRef) -> CompleteExport {
    let snapshot = b.open_snapshot(pin).await.unwrap();
    let mut pages = vec![];
    let mut cursor = None;
    let mut stream = ResourceId::new("terminal").unwrap();
    loop {
        let page = snapshot
            .export(cursor.as_ref(), PageSize::new(2).unwrap())
            .await
            .unwrap();
        cursor = page.next().cloned();
        if let Some(c) = &cursor {
            stream = c.stream().clone();
        }
        pages.push(page);
        if cursor.is_none() {
            break;
        }
    }
    CompleteExport::collect(pin.clone(), stream, pages, 1000).unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_probe_child() {
    let Ok(mode) = std::env::var("CDB_P3_PROBE") else {
        return;
    };
    let root = std::path::PathBuf::from(std::env::var_os("CDB_P3_ROOT").unwrap());
    let backend = FlureeBackend::create(options(&root)).await.unwrap();
    backend
        .admit(
            &IdempotencyKey::new("seed").unwrap(),
            &edge_batch("old-edge"),
        )
        .await
        .unwrap();
    let initial = backend.head().await.unwrap();
    let projection = if mode != "authority" {
        let p = RedbProjection::create(
            root.join("projection"),
            checkpoint(initial.clone()),
            GenerationOptions::default(),
        )
        .await
        .unwrap();
        p.build(
            &export(&backend, &initial).await,
            &checkpoint(initial.clone()),
        )
        .await
        .unwrap();
        Some(p)
    } else {
        None
    };
    let receipt = backend
        .admit(
            &IdempotencyKey::new("persisted-operation").unwrap(),
            &batch(),
        )
        .await
        .unwrap();
    let target = receipt.snapshot().clone();
    let expected = if matches!(mode.as_str(), "apply" | "rebuild-after") {
        target.clone()
    } else {
        initial.clone()
    };
    let marker = V::Object(
        [
            ("target".into(), snapshot_value(&target)),
            ("expected".into(), snapshot_value(&expected)),
            (
                "time".into(),
                V::string(receipt.transaction_time().canonical()),
            ),
        ]
        .into(),
    );
    let held = if let Some(p) = &projection {
        Some(p.open_generation(&initial).await.unwrap())
    } else {
        None
    };

    if let Some(projection) = &projection {
        match mode.as_str() {
            "apply" => {
                let page = backend
                    .changes(&initial, &target, None, PageSize::new(10).unwrap())
                    .await
                    .unwrap();
                assert!(page.next().is_none());
                for change in page.items() {
                    projection
                        .apply(change, &checkpoint(change.result().clone()))
                        .await
                        .unwrap();
                }
            }
            "rebuild-before" => {
                let marker = marker.clone();
                projection
                    .rebuild_live_with_before_publish_probe(
                        &export(&backend, &target).await,
                        &checkpoint(target.clone()),
                        move || ready_barrier(&marker),
                    )
                    .await
                    .unwrap();
                unreachable!("barrier must not return");
            }
            "rebuild-after" => {
                projection
                    .rebuild_live(
                        &export(&backend, &target).await,
                        &checkpoint(target.clone()),
                    )
                    .await
                    .unwrap();
            }
            "before-apply" => {
                let page = backend
                    .changes(&initial, &target, None, PageSize::new(10).unwrap())
                    .await
                    .unwrap();
                assert!(page.next().is_none());
                assert_eq!(page.items().len(), 1);
                let change = &page.items()[0];
                let marker = marker.clone();
                projection
                    .apply_with_before_commit_probe(
                        change,
                        &checkpoint(target.clone()),
                        move || ready_barrier(&marker),
                    )
                    .await
                    .unwrap();
                unreachable!("barrier must not return");
            }
            _ => panic!("unknown probe"),
        }
    }
    assert!(held.is_some() || mode == "authority");
    ready_barrier(&marker);
}
// Acknowledgment, not a sleep; timeout aborts without unwinding if parent fails.
fn ready_barrier(marker: &V) -> ! {
    println!(
        "P3_READY {}",
        String::from_utf8(marker.canonical_bytes(Limits::default()).unwrap()).unwrap()
    );
    std::io::stdout().flush().unwrap();
    let (_tx, rx) = std::sync::mpsc::channel::<()>();
    let _ = rx.recv_timeout(Duration::from_secs(120));
    std::process::abort();
}
fn killed_probe(root: &Path, mode: &str) -> V {
    let stderr = std::fs::File::create(root.join("child.stderr")).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "process_probe_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("CDB_P3_PROBE", mode)
        .env("CDB_P3_ROOT", root)
        .stdout(std::process::Stdio::piped())
        .stderr(stderr)
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            let line = line.unwrap();
            if let Some(i) = line.find("P3_READY ") {
                let _ = tx.send(line[i + 9..].to_string());
                break;
            }
        }
    });
    let result = rx.recv_timeout(Duration::from_secs(90));
    let _ = child.kill();
    let status = child.wait().unwrap();
    reader.join().unwrap();
    assert!(!status.success());
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9), "parent must SIGKILL, not unwind");
    }
    let line = result.unwrap_or_else(|e| {
        panic!(
            "probe {mode}: {e}; {}",
            std::fs::read_to_string(root.join("child.stderr")).unwrap()
        )
    });
    V::parse(line.as_bytes(), Limits::default()).unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn corrupt_derived_file_is_rebuilt_from_authority_in_a_new_directory() {
    let root = tempfile::tempdir().unwrap();
    let backend = FlureeBackend::create(options(root.path())).await.unwrap();
    let receipt = backend
        .admit(&IdempotencyKey::new("original").unwrap(), &batch())
        .await
        .unwrap();
    let pin = receipt.snapshot().clone();
    let dir = root.path().join("projection");
    let store = RedbProjection::create(&dir, checkpoint(pin.clone()), GenerationOptions::default())
        .await
        .unwrap();
    store
        .build(&export(&backend, &pin).await, &checkpoint(pin.clone()))
        .await
        .unwrap();
    drop(store);
    let file = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("generation-")
        })
        .unwrap();
    std::fs::write(&file, b"deliberately corrupt disposable test generation").unwrap();
    assert!(
        RedbProjection::open(&dir, checkpoint(pin.clone()), GenerationOptions::default())
            .await
            .is_err()
    );
    let replacement = RedbProjection::create(
        root.path().join("repaired"),
        checkpoint(pin.clone()),
        GenerationOptions::default(),
    )
    .await
    .unwrap();
    replacement
        .build(&export(&backend, &pin).await, &checkpoint(pin.clone()))
        .await
        .unwrap();
    assert!(replacement
        .open_view(&pin)
        .await
        .unwrap()
        .resource(&ResourceId::new("persisted").unwrap())
        .unwrap()
        .is_some());
    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"deliberately corrupt disposable test generation"
    );
    assert_eq!(backend.head().await.unwrap(), pin);
    assert_eq!(
        backend
            .receipt(&IdempotencyKey::new("original").unwrap())
            .await
            .unwrap()
            .unwrap(),
        receipt
    );
    println!("P3_CASE {{\"id\":\"P3-R007\",\"outcome\":\"passed\"}}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_exact_preparation_timeout_releases_no_bytes() {
    use cdb_engine::{
        compiler::{compile, QuerySource},
        execution::{execute, ExecutionOptions},
        options::CompileOptions,
    };
    use cdb_testkit::reference_fixture::FixtureBuilder;
    let mut builder = FixtureBuilder::new();
    builder.entity("s", Some("Start")).unwrap();
    let fixture = common_p3::NativeFixture::new(builder, common_p3::reader_policy(), 1).await;
    fixture
        .coordinator
        .reconcile(tokio::time::Instant::now() + Duration::from_secs(10))
        .await
        .unwrap();
    let old = fixture.store.checkpoint().await.unwrap().unwrap();
    fixture.store.set_before_apply_fault(true);
    fixture.store.set_before_publish_fault(true);
    fixture.advance();
    let provider = cdb_projection_redb::RedbViewProvider::new(
        fixture.coordinator.clone(),
        fixture.store.clone(),
        Duration::from_millis(50),
    )
    .unwrap();
    let draft = compile(
        QuerySource::inline(
            br#"{"about":[{"from":["s"],"match":"exact"}],"bounds":{"max_depth":1}}"#,
        ),
        None,
        &fixture.config,
        CompileOptions::default(),
    )
    .unwrap();
    let mut bytes = vec![];
    let error = execute(
        draft,
        fixture.backend.as_ref(),
        fixture.backend.as_ref(),
        &fixture.principal,
        &provider,
        ExecutionOptions::default(),
        &mut |b| {
            bytes.extend_from_slice(b);
            Ok(())
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind, cdb_core::ErrorKind::Deadline, "{error:?}");
    assert!(bytes.is_empty());
    assert_ne!(fixture.backend.head().await.unwrap(), *old.snapshot());
    assert_eq!(fixture.store.checkpoint().await.unwrap().unwrap(), old);
    fixture.store.set_before_apply_fault(false);
    fixture.store.set_before_publish_fault(false);
    drop(provider);
    fixture.shutdown().await;
    println!("P3_CASE {{\"id\":\"P3-R008\",\"outcome\":\"passed\"}}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_subscriber_retries_failed_apply_without_another_write() {
    let root = tempfile::tempdir().unwrap();
    let backend = Arc::new(FlureeBackend::create(options(root.path())).await.unwrap());
    let initial = backend.head().await.unwrap();
    let store = Arc::new(
        RedbProjection::create(
            root.path().join("projection"),
            checkpoint(initial.clone()),
            GenerationOptions::default(),
        )
        .await
        .unwrap(),
    );
    let projection_binding = checkpoint(initial.clone());
    let projection_source = Arc::new(GraphBackendProjectionSource::new(
        backend.clone(),
        projection_binding.schema().clone(),
        projection_binding.algorithm().clone(),
    ));
    let coordinator = Coordinator::start(
        projection_source,
        store.clone(),
        projection_binding,
        CoordinatorOptions::default(),
    )
    .unwrap();
    coordinator
        .wait_exact(
            &initial,
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
    let mut status = coordinator.status();
    store.set_before_apply_fault(true);
    let receipt = backend
        .admit(&IdempotencyKey::new("silent-retry").unwrap(), &batch())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                *status.borrow(),
                cdb_projection_redb::CoordinatorStatus::Degraded(_)
            ) {
                break;
            }
            status.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(
        store.checkpoint().await.unwrap().unwrap().snapshot(),
        &initial
    );
    assert!(store
        .open_view(&initial)
        .await
        .unwrap()
        .resource(&ResourceId::new("persisted").unwrap())
        .unwrap()
        .is_none());
    store.set_before_apply_fault(false); // No wakeup and no additional authority mutation.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(&*status.borrow(), cdb_projection_redb::CoordinatorStatus::Ready(cp) if cp.snapshot() == receipt.snapshot()) { break; }
            status.changed().await.unwrap();
        }
    }).await.unwrap();
    assert_eq!(backend.head().await.unwrap(), *receipt.snapshot());
    assert!(store
        .open_view(receipt.snapshot())
        .await
        .unwrap()
        .resource(&ResourceId::new("persisted").unwrap())
        .unwrap()
        .is_some());
    coordinator.shutdown().await.unwrap();
    println!("P3_CASE {{\"id\":\"P3-R006\",\"outcome\":\"passed\"}}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authority_and_projection_recover_after_process_kills() {
    for (i, mode) in [
        "authority",
        "before-apply",
        "apply",
        "rebuild-before",
        "rebuild-after",
    ]
    .into_iter()
    .enumerate()
    {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().to_path_buf();
        let marker = tokio::task::spawn_blocking(move || killed_probe(&path, mode))
            .await
            .unwrap();
        let target =
            snapshot_from_value(marker.field("target").unwrap(), Limits::default()).unwrap();
        let expected =
            snapshot_from_value(marker.field("expected").unwrap(), Limits::default()).unwrap();
        let backend = Arc::new(FlureeBackend::open(options(root.path())).await.unwrap());
        assert_eq!(backend.head().await.unwrap(), target);
        let receipt = backend
            .receipt(&IdempotencyKey::new("persisted-operation").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.snapshot(), &target);
        assert_eq!(
            receipt.transaction_time().canonical(),
            marker.field("time").unwrap().as_str().unwrap()
        );
        assert!(backend
            .open_snapshot(&target)
            .await
            .unwrap()
            .resource(&ResourceId::new("persisted").unwrap())
            .await
            .unwrap()
            .is_some());
        // Retrying the original request recovers its old receipt without new authority
        // writes. Projection recovery never reconstructs the authority from this input.
        assert_eq!(
            backend
                .admit(
                    &IdempotencyKey::new("persisted-operation").unwrap(),
                    &batch()
                )
                .await
                .unwrap(),
            receipt
        );
        assert_eq!(backend.head().await.unwrap(), target);
        if mode != "authority" {
            let dir = root.path().join("projection");
            let old_file = dir.join("generation-0.redb");
            let stage_file = dir.join("generation-1.redb");
            assert!(old_file.is_file());
            if mode == "rebuild-before" {
                assert!(stage_file.is_file(), "killed before stage cleanup");
                let stage = cdb_projection_redb::Database::open(
                    &stage_file,
                    &checkpoint(target.clone()),
                    Default::default(),
                )
                .unwrap();
                assert!(stage
                    .open_view(&target)
                    .unwrap()
                    .claim(&ClaimId::new("new-edge").unwrap())
                    .unwrap()
                    .is_some());
                drop(stage);
            }
            let unrelated = dir.join("unrelated.keep");
            std::fs::write(&unrelated, b"not managed").unwrap();
            let store = Arc::new(
                RedbProjection::open(
                    root.path().join("projection"),
                    checkpoint(target.clone()),
                    GenerationOptions::default(),
                )
                .await
                .unwrap(),
            );
            assert_eq!(
                store.checkpoint().await.unwrap().unwrap().snapshot(),
                &expected
            );
            assert!(old_file.is_file());
            assert_eq!(std::fs::read(&unrelated).unwrap(), b"not managed");
            if mode == "rebuild-before" {
                assert!(!stage_file.exists(), "reserved orphan removed on reopen");
            }
            let seed = backend
                .receipt(&IdempotencyKey::new("seed").unwrap())
                .await
                .unwrap()
                .unwrap();
            let held_cache = if mode.starts_with("rebuild-") {
                let held = store.open_generation(seed.snapshot()).await.unwrap();
                assert!(held
                    .claim(&ClaimId::new("old-edge").unwrap())
                    .unwrap()
                    .is_some());
                assert!(held
                    .claim(&ClaimId::new("new-edge").unwrap())
                    .unwrap()
                    .is_none());
                if mode == "rebuild-after" {
                    assert!(store.evict(seed.snapshot()).await.is_err());
                    assert!(old_file.is_file());
                }
                Some(held)
            } else {
                None
            };
            let old = store.open_generation(&expected).await.unwrap();
            let expected_edges = if expected == target { 2 } else { 1 };
            for (entity, direction) in [
                ("s", Direction::Outgoing),
                ("o", Direction::Incoming),
                ("s", Direction::Both),
            ] {
                let page = old
                    .incident(
                        &EntityId::new(entity).unwrap(),
                        direction,
                        PageSize::new(10).unwrap(),
                        None,
                    )
                    .unwrap();
                assert_eq!(page.items().len(), expected_edges);
                assert!(page.next().is_none());
            }
            assert_eq!(
                old.claim(&ClaimId::new("new-edge").unwrap())
                    .unwrap()
                    .is_some(),
                expected == target
            );
            assert!(old
                .claim(&ClaimId::new("old-edge").unwrap())
                .unwrap()
                .is_some());
            assert_eq!(
                old.resource(&ResourceId::new("persisted").unwrap())
                    .unwrap()
                    .is_some(),
                expected == target
            );
            let projection_binding = checkpoint(target.clone());
            let projection_source = Arc::new(GraphBackendProjectionSource::new(
                backend.clone(),
                projection_binding.schema().clone(),
                projection_binding.algorithm().clone(),
            ));
            let coordinator = Coordinator::start(
                projection_source,
                store.clone(),
                projection_binding,
                CoordinatorOptions::default(),
            )
            .unwrap();
            coordinator
                .reconcile(tokio::time::Instant::now() + Duration::from_secs(30))
                .await
                .unwrap();
            let view = coordinator
                .wait_exact(
                    &target,
                    tokio::time::Instant::now() + Duration::from_secs(30),
                )
                .await
                .unwrap();
            assert!(view
                .resource(&ResourceId::new("persisted").unwrap())
                .unwrap()
                .is_some());
            assert_eq!(
                store.checkpoint().await.unwrap().unwrap().snapshot(),
                &target
            );
            assert_eq!(old.checkpoint().snapshot(), &expected);
            assert_eq!(
                old.incident(
                    &EntityId::new("s").unwrap(),
                    Direction::Outgoing,
                    PageSize::new(10).unwrap(),
                    None
                )
                .unwrap()
                .items()
                .len(),
                expected_edges
            );
            coordinator.shutdown().await.unwrap();
            if let Some(held) = &held_cache {
                assert!(held
                    .claim(&ClaimId::new("old-edge").unwrap())
                    .unwrap()
                    .is_some());
                assert!(held
                    .claim(&ClaimId::new("new-edge").unwrap())
                    .unwrap()
                    .is_none());
                assert!(old_file.is_file());
            }
            drop(held_cache);
            drop(old);
            drop(view);
            drop(store);
        }
        drop(backend);
        println!(
            "P3_CASE {{\"id\":\"P3-R{:03}\",\"outcome\":\"passed\"}}",
            i + 1
        );
    }
}
