#[path = "../src/catalog.rs"]
mod catalog;
use cdb_core::{
    admission::*, claim::TypedLiteral, contracts::*, id::*, snapshot::*,
    storage_origin::RecordOrigin, CanonicalValue as V, Limits, Timestamp,
};
use cdb_engine::execution::{property_iri, ExecutionOptions, LandingCatalog};
use cdb_projection_redb::{Database, DatabaseOptions};
fn pin() -> SnapshotRef {
    SnapshotRef::new(
        BackendId::new("test").unwrap(),
        GraphPin::new(
            AuthorityId::new("a").unwrap(),
            GraphId::new("g").unwrap(),
            VersionId::new("opaque").unwrap(),
            ResourceId::new("cid").unwrap(),
        ),
    )
}
fn entity(id: &str, label: &str) -> ExportRecord {
    ExportRecord::Resource(
        DependencyRecord::new(
            "ctxql-resource/v1",
            ResourceId::new(id).unwrap(),
            ResourceKind::Label,
            vec![
                Fact::new(
                    property_iri("entity").unwrap(),
                    FactTerm::Literal(
                        TypedLiteral::new(
                            Iri::new("http://www.w3.org/2001/XMLSchema#boolean").unwrap(),
                            V::Bool(true),
                            None,
                        )
                        .unwrap(),
                    ),
                ),
                Fact::new(
                    property_iri("label").unwrap(),
                    FactTerm::Literal(
                        TypedLiteral::new(
                            Iri::new("http://www.w3.org/2001/XMLSchema#string").unwrap(),
                            V::string(label),
                            None,
                        )
                        .unwrap(),
                    ),
                ),
            ],
        )
        .unwrap(),
    )
}
fn origin(record: &ExportRecord, seq: u64, removed: bool) -> ExportRecord {
    ExportRecord::Resource(
        RecordOrigin::new(
            record,
            seq,
            Timestamp::from_millis(seq as i64).unwrap(),
            removed,
            Limits::default(),
        )
        .unwrap()
        .resource(Limits::default())
        .unwrap(),
    )
}
fn with_database(
    records: Vec<ExportRecord>,
    f: impl FnOnce(&dyn Fn(Timestamp, ExecutionOptions) -> cdb_core::Result<catalog::Catalog>),
) {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = pin();
    let export = CompleteExport::collect(
        snapshot.clone(),
        ResourceId::new("e").unwrap(),
        vec![Page::new(records, snapshot.clone(), None, PageSize::new(100).unwrap()).unwrap()],
        100,
    )
    .unwrap();
    let cp = ProjectionCheckpoint::new(
        snapshot.clone(),
        VersionId::new("ctxql-projection/v1").unwrap(),
        VersionId::new("gen").unwrap(),
        Iri::new("urn:algorithm").unwrap(),
    )
    .unwrap();
    let db = Database::create(
        &dir.path().join("db"),
        &export,
        &cp,
        DatabaseOptions::default(),
    )
    .unwrap();
    let view = db.open_view(&snapshot).unwrap();
    f(&|time, options| {
        catalog::prepare_catalog(&snapshot, time, &options, |size, cursor| {
            view.scan(size, cursor)
        })
    });
}
#[test]
fn multi_admission_origins_and_dependencies_are_temporal() {
    let a = entity("a", "Alpha");
    let b = entity("b", "Beta");
    with_database(
        vec![
            a.clone(),
            b.clone(),
            origin(&a, 1, false),
            origin(&b, 2, false),
        ],
        |prepare| {
            let options = ExecutionOptions {
                page_size: PageSize::new(1).unwrap(),
                ..Default::default()
            };
            let c = prepare(Timestamp::from_millis(1).unwrap(), options.clone()).unwrap();
            assert_eq!(c.identity(), &pin());
            assert_eq!(c.entries().len(), 2);
            assert!(c
                .entries()
                .iter()
                .all(|e| e.id.as_str() == "a" && e.dependencies.len() == 2));
            let c = prepare(Timestamp::from_millis(2).unwrap(), options).unwrap();
            assert_eq!(c.entries().len(), 4);
        },
    );
}
#[test]
fn return_to_old_image_is_not_backdated() {
    let a = entity("a", "A");
    let b = entity("a", "B");
    with_database(
        vec![
            a.clone(),
            origin(&a, 1, false),
            origin(&b, 2, false),
            origin(&a, 3, false),
        ],
        |prepare| {
            assert!(prepare(
                Timestamp::from_millis(2).unwrap(),
                ExecutionOptions::default()
            )
            .unwrap()
            .entries()
            .is_empty());
            let c = prepare(
                Timestamp::from_millis(3).unwrap(),
                ExecutionOptions::default(),
            )
            .unwrap();
            assert_eq!(c.entries().len(), 2);
            assert!(c.entries()[0].dependencies[1].as_str().contains("/3/"));
        },
    );
}
#[test]
fn missing_removed_and_mismatched_origins_fail_closed() {
    let a = entity("a", "A");
    let b = entity("a", "B");
    for records in [
        vec![a.clone()],
        vec![a.clone(), origin(&a, 1, true)],
        vec![a.clone(), origin(&b, 1, false)],
    ] {
        with_database(records, |prepare| {
            assert!(prepare(
                Timestamp::from_millis(9).unwrap(),
                ExecutionOptions::default()
            )
            .is_err())
        });
    }
}
#[test]
fn catalog_limits_and_interruption_do_not_return_partial_entries() {
    let a = entity("a", "A");
    with_database(vec![a.clone(), origin(&a, 1, false)], |prepare| {
        for options in [
            ExecutionOptions {
                max_work: 0,
                ..Default::default()
            },
            ExecutionOptions {
                max_retained_bytes: 1,
                ..Default::default()
            },
            ExecutionOptions {
                max_records: 1,
                ..Default::default()
            },
            ExecutionOptions {
                deadline: Some(std::time::Instant::now()),
                ..Default::default()
            },
        ] {
            assert!(prepare(Timestamp::from_millis(9).unwrap(), options).is_err());
        }
    });
}
