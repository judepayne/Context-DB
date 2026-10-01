use cdb_core::{
    admission::*, claim::*, contracts::*, id::*, snapshot::*, CanonicalValue as V, Limits,
    Timestamp,
};
use cdb_projection_redb::{Database, DatabaseOptions};
fn pin(rev: &str) -> SnapshotRef {
    SnapshotRef::new(
        BackendId::new("test").unwrap(),
        GraphPin::new(
            AuthorityId::new("test:authority").unwrap(),
            GraphId::new("g").unwrap(),
            VersionId::new(rev).unwrap(),
            ResourceId::new(format!("receipt:{rev}")).unwrap(),
        ),
    )
}
fn cp(rev: &str) -> ProjectionCheckpoint {
    ProjectionCheckpoint::new(
        pin(rev),
        VersionId::new("ctxql-projection/v1").unwrap(),
        VersionId::new("generation:1").unwrap(),
        Iri::new("urn:algorithm:raw").unwrap(),
    )
    .unwrap()
}
fn time() -> Timestamp {
    Timestamp::parse("1965-01-02T03:04:05Z").unwrap()
}
fn candidate(id: &str, subject: &str, object: Option<&str>) -> CandidateClaim {
    let mut v=V::parse(br#"{"claim_id":"c","subject_id":"s","relation":"urn:rel","object_id":{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#decimal","value":9007199254740993.0123456789,"language":null},"relation_type":"urn:relation-type","subject_type":"urn:subject-type","object_type":"urn:object-type","claim_type":"urn:claim-type","confidence":0.75,"grounding_level":"claim_only"}"#,Limits::default()).unwrap();
    set(&mut v, "claim_id", V::string(id));
    set(&mut v, "subject_id", V::string(subject));
    if let Some(o) = object {
        set(&mut v, "object_id", V::string(o));
    }
    CandidateClaim::from_value(&v).unwrap()
}
fn set(v: &mut V, k: &str, x: V) {
    let V::Object(o) = v else { panic!() };
    o.insert(k.into(), x);
}
fn claim(id: &str, subject: &str, object: Option<&str>) -> ExportRecord {
    ExportRecord::Claim(Box::new(AdmittedClaim::assign(
        candidate(id, subject, object),
        time(),
    )))
}
fn resource(id: &str, kind: ResourceKind, target: &str) -> DependencyRecord {
    DependencyRecord::new(
        "ctxql-resource/v1",
        ResourceId::new(id).unwrap(),
        kind,
        vec![Fact::new(
            Iri::new("urn:fact").unwrap(),
            FactTerm::Reference(ResourceId::new(target).unwrap()),
        )],
    )
    .unwrap()
}
fn export(rev: &str, records: Vec<ExportRecord>) -> CompleteExport {
    CompleteExport::collect(
        pin(rev),
        ResourceId::new("export").unwrap(),
        vec![Page::new(records, pin(rev), None, PageSize::new(100).unwrap()).unwrap()],
        100,
    )
    .unwrap()
}
fn batch(a: &str, b: &str, changes: Vec<RecordChange>) -> ChangeBatch {
    ChangeBatch::new(
        "ctxql-change/v1",
        pin(a),
        pin(b),
        changes,
        Limits::default(),
    )
    .unwrap()
}
fn add(r: ExportRecord) -> RecordChange {
    match r {
        ExportRecord::Claim(c) => RecordChange::ClaimAdded(c),
        ExportRecord::Resource(r) => RecordChange::Resource(ResourceChange::Add(r)),
        ExportRecord::Lifecycle {
            assertion,
            transaction_time,
        } => RecordChange::LifecycleAdded {
            assertion,
            transaction_time,
        },
        ExportRecord::Artifact(a) => RecordChange::ArtifactAdded(a),
    }
}
fn size(n: usize) -> PageSize {
    PageSize::new(n).unwrap()
}
fn id(s: &str) -> ClaimId {
    ClaimId::new(s).unwrap()
}
#[test]
fn durable_atomic_apply_and_held_read_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let db = Database::create(
        &path,
        &export("0", vec![claim("a", "s", Some("t"))]),
        &cp("0"),
        DatabaseOptions::default(),
    )
    .unwrap();
    let held = db.open_view(&pin("0")).unwrap();
    let delta = batch("0", "1", vec![add(claim("b", "s", Some("t")))]);
    db.apply(&delta, &cp("1")).unwrap();
    assert!(held.claim(&id("b")).unwrap().is_none());
    assert!(held.claim(&id("a")).unwrap().is_some());
    assert!(db.open_view(&pin("0")).is_err());
    assert!(db
        .open_view(&pin("1"))
        .unwrap()
        .claim(&id("b"))
        .unwrap()
        .is_some());
    drop(held);
    drop(db);
    let db = Database::open(&path, &cp("1"), DatabaseOptions::default()).unwrap();
    assert_eq!(db.checkpoint().unwrap(), cp("1"));
    assert!(Database::create(
        &path,
        &export("0", vec![]),
        &cp("0"),
        DatabaseOptions::default()
    )
    .is_err());
}
#[test]
fn before_commit_fault_reopens_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let db = Database::create(
        &path,
        &export("0", vec![]),
        &cp("0"),
        DatabaseOptions::default(),
    )
    .unwrap();
    db.set_before_commit_fault(true);
    assert!(db
        .apply(&batch("0", "1", vec![add(claim("a", "s", None))]), &cp("1"))
        .is_err());
    assert_eq!(db.checkpoint().unwrap(), cp("0"));
    drop(db);
    let db = Database::open(&path, &cp("0"), DatabaseOptions::default()).unwrap();
    assert!(db
        .open_view(&pin("0"))
        .unwrap()
        .claim(&id("a"))
        .unwrap()
        .is_none());
}
#[test]
fn duplicates_gaps_collisions_and_metadata_only() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(
        &dir.path().join("db"),
        &export("0", vec![claim("a", "s", None)]),
        &cp("0"),
        DatabaseOptions::default(),
    )
    .unwrap();
    let empty = batch("0", "1", vec![]);
    db.apply(&empty, &cp("1")).unwrap();
    db.apply(&empty, &cp("1")).unwrap();
    assert!(db
        .apply(&batch("0", "1", vec![add(claim("b", "s", None))]), &cp("1"))
        .is_err());
    assert!(db.apply(&batch("0", "2", vec![]), &cp("2")).is_err());
    assert!(db
        .apply(
            &batch(
                "1",
                "2",
                vec![add(ExportRecord::Resource(resource(
                    "a",
                    ResourceKind::Label,
                    "x"
                )))]
            ),
            &cp("2")
        )
        .is_err());
    assert!(db
        .apply(&batch("1", "2", vec![add(claim("a", "s", None))]), &cp("2"))
        .is_err());
    assert_eq!(db.checkpoint().unwrap(), cp("1"));
}
#[test]
fn mutable_previous_kind_and_hash() {
    let dir = tempfile::tempdir().unwrap();
    let r = resource("r", ResourceKind::Label, "a");
    let hash = ContentHash::of_bytes(&r.projection().canonical_bytes(Limits::default()).unwrap());
    let db = Database::create(
        &dir.path().join("db"),
        &export("0", vec![ExportRecord::Resource(r)]),
        &cp("0"),
        DatabaseOptions::default(),
    )
    .unwrap();
    for (kind, previous) in [
        (ResourceKind::Identity, hash.clone()),
        (ResourceKind::Label, ContentHash::of_bytes(b"bad")),
    ] {
        assert!(db
            .apply(
                &batch(
                    "0",
                    "1",
                    vec![RecordChange::Resource(ResourceChange::ReplaceMutable {
                        previous,
                        record: resource("r", kind, "b")
                    })]
                ),
                &cp("1")
            )
            .is_err());
    }
    let r = resource("r", ResourceKind::Label, "b");
    db.apply(
        &batch(
            "0",
            "1",
            vec![RecordChange::Resource(ResourceChange::ReplaceMutable {
                previous: hash,
                record: r.clone(),
            })],
        ),
        &cp("1"),
    )
    .unwrap();
    assert_eq!(
        db.open_view(&pin("1"))
            .unwrap()
            .entity(&EntityId::new("r").unwrap())
            .unwrap(),
        Some(vec![r.clone()])
    );
    db.apply(
        &batch(
            "1",
            "2",
            vec![RecordChange::Resource(ResourceChange::RetractMutable {
                id: r.id().clone(),
                kind: r.kind(),
                previous: ContentHash::of_bytes(
                    &r.projection().canonical_bytes(Limits::default()).unwrap(),
                ),
            })],
        ),
        &cp("2"),
    )
    .unwrap();
    assert!(db
        .open_view(&pin("2"))
        .unwrap()
        .resource(r.id())
        .unwrap()
        .is_none());
}
#[test]
fn literal_lifecycle_equal_triples_and_self_loop_pages() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = candidate("life", "a", Some("event")).projection();
    set(&mut v, "relation", V::string("ctxql:retracted_by"));
    let life = ExportRecord::Lifecycle {
        assertion: LifecycleAssertion::from_value(&v).unwrap(),
        transaction_time: time(),
    };
    let records = vec![
        claim("a", "s", Some("s")),
        claim("b", "s", Some("s")),
        claim("literal", "s", None),
        life.clone(),
        ExportRecord::Resource(resource("event", ResourceKind::LifecycleEvent, "anything")),
    ];
    let db = Database::create(
        &dir.path().join("db"),
        &export("0", records.clone()),
        &cp("0"),
        DatabaseOptions::default(),
    )
    .unwrap();
    let view = db.open_view(&pin("0")).unwrap();
    let s = EntityId::new("s").unwrap();
    let mut cursor = None;
    let mut ids = vec![];
    loop {
        let p = view
            .incident(&s, Direction::Both, size(1), cursor.as_ref())
            .unwrap();
        ids.extend(p.items().iter().map(|c| c.id().as_str().to_string()));
        cursor = p.next().cloned();
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(ids, vec!["a", "b", "literal"]);
    assert_eq!(
        view.incident(&s, Direction::Incoming, size(10), None)
            .unwrap()
            .items()
            .len(),
        2
    );
    assert_eq!(view.claim(&id("life")).unwrap(), life.claim());
    assert_eq!(
        view.lifecycle(&id("a"), size(1), None).unwrap().items(),
        std::slice::from_ref(&life)
    );
    assert_eq!(
        view.incident(
            &EntityId::new("a").unwrap(),
            Direction::Outgoing,
            size(1),
            None
        )
        .unwrap()
        .items(),
        &[life.claim().unwrap()]
    );
    assert_eq!(
        view.incident(
            &EntityId::new("event").unwrap(),
            Direction::Incoming,
            size(1),
            None
        )
        .unwrap()
        .items()
        .len(),
        1
    );
    let p = view.incident(&s, Direction::Both, size(1), None).unwrap();
    assert!(view
        .incident(&s, Direction::Outgoing, size(1), p.next())
        .is_err());
    assert!(view.scan(size(1), p.next()).is_err());
    let mut all = vec![];
    let mut cursor = None;
    loop {
        let p = view.scan(size(2), cursor.as_ref()).unwrap();
        all.extend(p.items().to_vec());
        cursor = p.next().cloned();
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(all.len(), records.len());
    assert!(all.contains(&life));
}
#[test]
fn staged_references_and_build_validation_limits() {
    let dir = tempfile::tempdir().unwrap();
    let a = claim("a", "s", None);
    assert!(Database::create(
        &dir.path().join("dup"),
        &export("0", vec![a.clone(), a]),
        &cp("0"),
        DatabaseOptions::default()
    )
    .is_err());
    let mut v = candidate("life", "a", Some("b")).projection();
    set(&mut v, "relation", V::string("ctxql:superseded_by"));
    let life = ExportRecord::Lifecycle {
        assertion: LifecycleAssertion::from_value(&v).unwrap(),
        transaction_time: time(),
    };
    assert!(Database::create(
        &dir.path().join("refs"),
        &export("0", vec![life.clone()]),
        &cp("0"),
        DatabaseOptions::default()
    )
    .is_err());
    let db = Database::create(
        &dir.path().join("db"),
        &export("0", vec![]),
        &cp("0"),
        DatabaseOptions {
            max_page_records: 1,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(db
        .apply(
            &batch(
                "0",
                "1",
                vec![
                    add(life.clone()),
                    add(ExportRecord::Resource(resource(
                        "a",
                        ResourceKind::Label,
                        "b"
                    ))),
                    add(claim("b", "s", None))
                ]
            ),
            &cp("1")
        )
        .is_err());
    db.apply(
        &batch(
            "0",
            "1",
            vec![
                add(life),
                add(claim("a", "s", None)),
                add(claim("b", "s", None)),
            ],
        ),
        &cp("1"),
    )
    .unwrap();
    assert!(db
        .open_view(&pin("1"))
        .unwrap()
        .scan(size(2), None)
        .is_err());
}
#[test]
fn corrupt_decode_is_error_not_absence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let db = Database::create(
        &path,
        &export("0", vec![claim("a", "s", None)]),
        &cp("0"),
        DatabaseOptions::default(),
    )
    .unwrap();
    drop(db);
    {
        let db = redb::Database::open(&path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn
                .open_table(redb::TableDefinition::<&str, &[u8]>::new("records-v1"))
                .unwrap();
            t.insert("resource:a", b"corrupt".as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }
    let db = Database::open(&path, &cp("0"), DatabaseOptions::default()).unwrap();
    let view = db.open_view(&pin("0")).unwrap();
    assert!(view.claim(&id("a")).is_err());
    assert!(view.scan(size(1), None).is_err());
    assert!(view
        .incident(&EntityId::new("s").unwrap(), Direction::Both, size(1), None)
        .is_err());
}
