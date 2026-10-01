use cdb_core::{
    admission::{DependencyRecord, ExportRecord, Fact, FactTerm, ResourceKind},
    claim::TypedLiteral,
    id::{Iri, ResourceId},
    storage_origin::RecordOrigin,
    CanonicalValue as V, Limits, Timestamp,
};
fn record(label: &str) -> ExportRecord {
    ExportRecord::Resource(
        DependencyRecord::new(
            "ctxql-resource/v1",
            ResourceId::new("s").unwrap(),
            ResourceKind::Label,
            vec![Fact::new(
                Iri::new("https://fixture/label").unwrap(),
                FactTerm::Literal(
                    TypedLiteral::new(
                        Iri::new("http://www.w3.org/2001/XMLSchema#string").unwrap(),
                        V::string(label),
                        None,
                    )
                    .unwrap(),
                ),
            )],
        )
        .unwrap(),
    )
}
#[test]
fn origin_round_trip_preserves_version_not_just_image_hash() {
    let limits = Limits::default();
    let a = record("A");
    let b = record("B");
    let t = Timestamp::from_millis(-1).unwrap();
    let first = RecordOrigin::new(&a, 1, t, false, limits).unwrap();
    let second = RecordOrigin::new(&b, 2, t, false, limits).unwrap();
    let third = RecordOrigin::new(&a, 3, t, false, limits).unwrap();
    assert_eq!(first.image(), third.image());
    assert_ne!(first.id().unwrap(), third.id().unwrap());
    assert!(!second.matches(&a, limits).unwrap());
    assert_eq!(
        RecordOrigin::from_resource(&third.resource(limits).unwrap(), limits)
            .unwrap()
            .unwrap(),
        third
    );
    assert_eq!(third.sequence(), 3);
    assert_eq!(third.time(), t);
    assert!(!third.removed());
}
#[test]
fn origins_are_immutable_and_identity_bound() {
    let limits = Limits::default();
    let origin = RecordOrigin::new(
        &record("A"),
        1,
        Timestamp::from_millis(0).unwrap(),
        true,
        limits,
    )
    .unwrap();
    let resource = origin.resource(limits).unwrap();
    assert!(!resource.kind().mutable());
    let forged = DependencyRecord::new(
        "ctxql-resource/v1",
        ResourceId::new(format!("{}x", resource.id().as_str())).unwrap(),
        resource.kind(),
        resource.facts().to_vec(),
    )
    .unwrap();
    assert!(RecordOrigin::from_resource(&forged, limits).is_err());
    assert!(RecordOrigin::new(&record("A"), 0, origin.time(), false, limits).is_err());
}
