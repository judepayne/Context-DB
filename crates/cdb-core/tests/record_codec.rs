mod common;
use cdb_core::{
    admission::*, artifact::*, claim::*, id::*, record_codec::*, snapshot::*, CanonicalValue as V,
    Limits, Timestamp,
};
use common::*;
fn time() -> Timestamp {
    Timestamp::parse("1965-01-02T03:04:05.123Z").unwrap()
}
fn artifact() -> PublishedArtifact {
    let bytes = vec![0, 255, 128, b'\n', b'"', 0];
    PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new("urn:文件").unwrap(),
            VersionId::new("版本:1").unwrap(),
            ContentHash::of_bytes(&bytes),
        ),
        bytes,
        Limits::default(),
    )
    .unwrap()
}
fn resource(kind: ResourceKind) -> DependencyRecord {
    DependencyRecord::new(
        "ctxql-resource/v1",
        ResourceId::new("资源:α").unwrap(),
        kind,
        vec![
            Fact::new(
                Iri::new("urn:ref").unwrap(),
                FactTerm::Reference(ResourceId::new("other").unwrap()),
            ),
            Fact::new(
                Iri::new("urn:number").unwrap(),
                FactTerm::Literal(
                    TypedLiteral::new(
                        Iri::new("http://www.w3.org/2001/XMLSchema#decimal").unwrap(),
                        json("9007199254740993.0123456789"),
                        None,
                    )
                    .unwrap(),
                ),
            ),
        ],
    )
    .unwrap()
}
#[test]
fn all_records_and_changes_lossless() {
    let l = Limits::default();
    let mut c = candidate("声明:1").projection();
    set(
        &mut c,
        "ext",
        json(r#"{"urn:extra":{"large":9007199254740993,"ordered":[1e-20,"你好",null]}}"#),
    );
    set(&mut c, "valid_time", V::string("1900-01-01T00:00:00Z"));
    set(
        &mut c,
        "source_observed_at",
        V::string("1960-01-01T00:00:00Z"),
    );
    let c = CandidateClaim::from_value(&c).unwrap();
    let mut records = vec![
        ExportRecord::Claim(Box::new(AdmittedClaim::assign(c.clone(), time()))),
        ExportRecord::Artifact(artifact()),
    ];
    for relation in [
        "ctxql:superseded_by",
        "ctxql:contradicted_by",
        "ctxql:retracted_by",
    ] {
        let mut v = c.projection();
        set(&mut v, "relation", V::string(relation));
        set(&mut v, "object_id", V::string("replacement"));
        records.push(ExportRecord::Lifecycle {
            assertion: LifecycleAssertion::from_value(&v).unwrap(),
            transaction_time: time(),
        });
    }
    for kind in [
        ResourceKind::Ontology,
        ResourceKind::Label,
        ResourceKind::Policy,
        ResourceKind::Identity,
        ResourceKind::SourceDescriptor,
        ResourceKind::ArtifactDescriptor,
        ResourceKind::RunDescriptor,
        ResourceKind::LifecycleEvent,
    ] {
        records.push(ExportRecord::Resource(resource(kind)));
    }
    for r in records {
        let bytes = encode_record(&r, l).unwrap();
        assert_eq!(decode_record(&bytes, l).unwrap(), r);
        assert_eq!(
            decode_record(&bytes, l).unwrap().identity_key(),
            r.identity_key()
        );
        let c = match r {
            ExportRecord::Claim(c) => RecordChange::ClaimAdded(c),
            ExportRecord::Lifecycle {
                assertion,
                transaction_time,
            } => RecordChange::LifecycleAdded {
                assertion,
                transaction_time,
            },
            ExportRecord::Artifact(a) => RecordChange::ArtifactAdded(a),
            ExportRecord::Resource(r) => RecordChange::Resource(ResourceChange::Add(r)),
        };
        assert_eq!(decode_change(&encode_change(&c, l).unwrap(), l).unwrap(), c);
    }
    for r in [
        ResourceChange::ReplaceMutable {
            previous: ContentHash::of_bytes(b"old"),
            record: resource(ResourceKind::Label),
        },
        ResourceChange::RetractMutable {
            previous: ContentHash::of_bytes(b"old"),
            id: ResourceId::new("x").unwrap(),
            kind: ResourceKind::Policy,
        },
    ] {
        let c = RecordChange::Resource(r);
        assert_eq!(decode_change(&encode_change(&c, l).unwrap(), l).unwrap(), c);
    }
}
#[test]
fn typed_literals_preserve_bits_and_lexical_values() {
    for (datatype, value, language) in [
        (
            "http://www.w3.org/2001/XMLSchema#integer",
            json("9007199254740993"),
            None,
        ),
        (
            "http://www.w3.org/2001/XMLSchema#float",
            json(r#"{"format":"binary32","bits":"80000000"}"#),
            None,
        ),
        (
            "http://www.w3.org/2001/XMLSchema#double",
            json(r#"{"format":"binary64","bits":"3ff0000000000001"}"#),
            None,
        ),
        (
            "http://www.w3.org/2001/XMLSchema#boolean",
            V::Bool(true),
            None,
        ),
        (
            "http://www.w3.org/2001/XMLSchema#dateTime",
            V::string("1960-01-01T00:00:00Z"),
            None,
        ),
        (
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString",
            V::string("café 漢字"),
            Some("fr-CA".to_owned()),
        ),
        ("urn:opaque:type", V::string("0001:α"), None),
    ] {
        let mut v = candidate("typed").projection();
        set(
            &mut v,
            "object_id",
            TypedLiteral::new(Iri::new(datatype).unwrap(), value, language)
                .unwrap()
                .projection(),
        );
        let r = ExportRecord::Claim(Box::new(AdmittedClaim::assign(
            CandidateClaim::from_value(&v).unwrap(),
            time(),
        )));
        assert_eq!(
            decode_record(
                &encode_record(&r, Limits::default()).unwrap(),
                Limits::default()
            )
            .unwrap(),
            r
        );
    }
}
#[test]
fn full_snapshot_checkpoint() {
    let l = Limits::default();
    let s = pin("rev:你好");
    assert_eq!(snapshot_from_value(&snapshot_value(&s), l).unwrap(), s);
    let c = ProjectionCheckpoint::new(
        s,
        VersionId::new("ctxql-projection/v1").unwrap(),
        VersionId::new("gen:2").unwrap(),
        Iri::new("urn:algorithm:v1").unwrap(),
    )
    .unwrap();
    assert_eq!(checkpoint_from_value(&checkpoint_value(&c), l).unwrap(), c);
    let mut v = snapshot_value(c.snapshot());
    set(&mut v, "extra", V::Null);
    assert!(snapshot_from_value(&v, l).is_err());
}
#[test]
fn rejects_corruption_and_limits() {
    let l = Limits::default();
    let r = ExportRecord::Artifact(artifact());
    let bytes = encode_record(&r, l).unwrap();
    for n in 0..bytes.len() {
        assert!(decode_record(&bytes[..n], l).is_err());
    }
    let text = String::from_utf8(bytes.clone()).unwrap();
    for bad in [
        text.replace("ctxql-storage/v1", "ctxql-storage/v2"),
        text.replace("00ff80", "01ff80"),
        text.replace("00ff80", "00FF80"),
        text.replace("00ff80", "0ff80"),
        text.replace("\"schema\":", "\"schema\":null,\"schema\":"),
        text.replace("\"payload\":", "\"unknown\":null,\"payload\":"),
    ] {
        assert!(decode_record(bad.as_bytes(), l).is_err());
    }
    assert!(decode_record(&[255], l).is_err());
    for tiny in [
        Limits::new(1, 64, 100000, 1000000, 1000000).unwrap(),
        Limits::new(1000000, 1, 100000, 1000000, 1000000).unwrap(),
        Limits::new(1000000, 64, 1, 1000000, 1000000).unwrap(),
        Limits::new(1000000, 64, 100000, 1, 1000000).unwrap(),
    ] {
        assert!(decode_record(&bytes, tiny).is_err());
    }
    assert!(encode_record(&r, Limits::new(1000, 64, 1000, 1000, 1).unwrap()).is_err());
    let bad = RecordChange::Resource(ResourceChange::RetractMutable {
        id: ResourceId::new("x").unwrap(),
        kind: ResourceKind::SourceDescriptor,
        previous: ContentHash::of_bytes(b"x"),
    });
    assert!(encode_change(&bad, l).is_err());
}
