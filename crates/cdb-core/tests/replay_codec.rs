mod common;
use cdb_core::{artifact::*, id::*, replay::*, snapshot::SnapshotRef, CanonicalValue as V, Limits};

fn run(snapshot: SnapshotRef, functions: bool) -> ExecutionRun {
    let l = Limits::default();
    let bytes = b" { \"value\" : 1 } \n".to_vec();
    let reference = ArtifactRef::new(
        Iri::new("https://example.org/function").unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(&bytes),
    );
    let artifact = PublishedArtifact::new(reference.clone(), bytes, l).unwrap();
    let manifest =
        FunctionManifest::from_published(ResourceId::new("function").unwrap(), &artifact, l)
            .unwrap();
    assert_ne!(
        manifest.hash(),
        &ContentHash::of_bytes(&manifest.content().canonical_bytes(l).unwrap())
    );
    let selector = ResourceId::new("selector").unwrap();
    let footprint = ReadFootprint::new(
        "ctxql-read-footprint/v1",
        snapshot.clone(),
        vec![
            ReadDependency::Claim(ClaimId::new("claim").unwrap()),
            ReadDependency::Lifecycle(ClaimId::new("event").unwrap()),
            ReadDependency::Resource(ResourceId::new("resource").unwrap()),
            ReadDependency::Fact {
                resource: ResourceId::new("resource").unwrap(),
                predicate: Iri::new("https://example.org/p").unwrap(),
            },
            ReadDependency::NegativeLookup {
                descriptor: ResourceId::new("scope").unwrap(),
            },
            ReadDependency::Artifact(reference.clone()),
            ReadDependency::SourceSelector {
                descriptor: selector.clone(),
                source: SourceId::new("source").unwrap(),
                version: ContentHash::of_bytes(b"source"),
            },
            ReadDependency::OrderingDescriptor(ResourceId::new("order").unwrap()),
        ],
        vec![selector],
    )
    .unwrap();
    ExecutionRun::new(ExecutionRunInput {
        schema: "ctxql-execution-run/v1".into(),
        id: RunId::new("legacy").unwrap(),
        query: reference.clone(),
        profile: Some(reference.clone()),
        config: reference,
        engine: EngineIdentity::new(
            Iri::new("https://example.org/engine").unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(b"build"),
        ),
        plan_hash: ContentHash::of_bytes(b"plan"),
        response_hash: ContentHash::of_bytes(b"response"),
        snapshot,
        as_of: cdb_core::Timestamp::parse("2024-01-01T00:00:00Z").unwrap(),
        landings: vec![],
        functions: if functions {
            vec![FunctionCallSummary::new(
                manifest,
                vec![ContentHash::of_bytes(b"in")],
                vec![ContentHash::of_bytes(b"out")],
            )
            .unwrap()]
        } else {
            vec![]
        },
        footprint,
    })
    .unwrap()
}
#[test]
fn lossless_noncanonical_manifest_and_empty_functions() {
    let l = Limits::default();
    for functions in [false, true] {
        let run = run(common::pin("a"), functions);
        assert_eq!(ExecutionRun::read(&run.bytes(l).unwrap(), l).unwrap(), run);
        let key = CoreSummaryKey::new(run.id().clone());
        assert_eq!(
            key.from_record(&key.to_record(&run, l).unwrap(), l)
                .unwrap(),
            run
        );
        assert!(!key
            .descriptor_id()
            .unwrap()
            .as_str()
            .starts_with(cdb_core::storage_origin::INTERNAL_PREFIX));
    }
}
#[test]
fn strict_schema_hash_bounds_and_key_binding() {
    let l = Limits::default();
    let run = run(common::pin("a"), true);
    for (field, value) in [
        ("schema", V::string("ctxql-execution-run/v2")),
        ("extra", V::Null),
        ("plan_hash", V::string("bad")),
    ] {
        let mut v = run.projection();
        let V::Object(o) = &mut v else { unreachable!() };
        o.insert(field.into(), value);
        assert!(ExecutionRun::from_value(&v, l).is_err());
    }
    let tiny = Limits::new(1, 1, 1, 1, 1).unwrap();
    assert!(ExecutionRun::read(&run.bytes(l).unwrap(), tiny).is_err());
    assert!(ExecutionRun::from_value(&run.projection(), tiny).is_err());
    let mut nested = run.projection();
    let V::Object(root) = &mut nested else {
        unreachable!()
    };
    let V::Array(functions) = root.get_mut("functions").unwrap() else {
        unreachable!()
    };
    let V::Object(function) = &mut functions[0] else {
        unreachable!()
    };
    function.insert("unknown".into(), V::Null);
    assert!(ExecutionRun::from_value(&nested, l).is_err());
    let other = CoreSummaryKey::new(RunId::new("other").unwrap());
    assert!(other.to_record(&run, l).is_err());
    let key = CoreSummaryKey::new(run.id().clone());
    let record = key.to_record(&run, l).unwrap();
    assert!(other.from_record(&record, l).is_err());
    use cdb_core::admission::*;
    let ExportRecord::Resource(r) = record else {
        unreachable!()
    };
    let FactTerm::Literal(literal) = r.facts()[0].term() else {
        unreachable!()
    };
    let mut envelope = V::parse(
        literal
            .projection()
            .field("value")
            .unwrap()
            .as_str()
            .unwrap()
            .as_bytes(),
        l,
    )
    .unwrap();
    let V::Object(o) = &mut envelope else {
        unreachable!()
    };
    o.insert(
        "hash".into(),
        V::string(ContentHash::of_bytes(b"tampered").as_str()),
    );
    let bad = ExportRecord::Resource(
        DependencyRecord::new(
            "ctxql-resource/v1",
            r.id().clone(),
            ResourceKind::RunDescriptor,
            vec![Fact::new(
                Iri::new(LEGACY_RUN_PAYLOAD).unwrap(),
                FactTerm::Literal(
                    cdb_core::claim::TypedLiteral::new(
                        Iri::new("http://www.w3.org/2001/XMLSchema#string").unwrap(),
                        V::string(String::from_utf8(envelope.canonical_bytes(l).unwrap()).unwrap()),
                        None,
                    )
                    .unwrap(),
                ),
            )],
        )
        .unwrap(),
    );
    assert!(key.from_record(&bad, l).is_err());
    assert!(ExecutionRun::read(b"{\"schema\":1,\"schema\":2}", l).is_err());
}
