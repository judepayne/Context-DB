use cdb_core::projection::{NormalizedQuery, SemanticConfig};
use cdb_core::{CanonicalValue, CanonicalValue as V, Limits};

fn value(text: &str) -> CanonicalValue {
    CanonicalValue::parse(text.as_bytes(), Limits::default()).unwrap()
}

#[test]
fn normalized_structure_preserves_language_bounds_predicates_and_function_registry() {
    let query = value(
        r#"{
      "about":[{"from":["Acme"],"to":null,"match":"exact"}],
      "bounds":{"as_of":"2026-01-01T00:00:00.000Z","max_depth":2,
        "seed_limit":2,"fanout_limit":4,"max_claims":16,"path_limit":8,
        "min_confidence":0.25,"meta:ext:permitted_region":"EMEA"},
      "walk":{"direction":"outgoing","predicates":[["meta:confidence",">=","bound:min_confidence"]]},
      "filter":{"predicates":[]},
      "return":{"claims":true,"paths":true,"evidence":false,"explain":false}
    }"#,
    );
    assert_eq!(
        NormalizedQuery::from_value(&query).unwrap().projection(),
        query
    );
    let config = value(
        r#"{
      "name":"test/config","version":"1",
      "runtime":{"candidate_order":["depth asc"],"path_ranking":["shorter_path"],"cycle_policy":"no_repeated_claim"},
      "fields":{},"external_functions":{"risk/score":{"version":"1",
        "manifest_uri":"ctxql:function/risk/score@1",
        "manifest_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "deterministic":true}}
    }"#,
    );
    assert_eq!(
        SemanticConfig::from_value(&config).unwrap().projection(),
        config
    );
}

#[test]
fn canonical_hash_equivalence_and_distinctions() {
    use cdb_core::{
        canonical::{CanonicalProjection, Domain},
        id::ContentHash,
    };
    let hash = |v: V| {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("name".into(), V::string("fixture/f"));
        fields.insert("version".into(), V::string("1"));
        fields.insert(
            "manifest_hash".into(),
            V::string(ContentHash::of_bytes(b"manifest").as_str()),
        );
        fields.insert("call_index".into(), V::integer(0));
        fields.insert("value".into(), v);
        CanonicalProjection::from_payload(Domain::FunctionInput, V::Object(fields))
            .unwrap()
            .hash(Limits::default())
            .unwrap()
    };
    assert_eq!(
        hash(value(r#"{"b":2,"a":1.0}"#)),
        hash(value(r#"{"a":1e0,"b":2}"#))
    );
    assert_eq!(hash(value("-0.0")), hash(value("0")));
    assert_ne!(hash(value("[1,2]")), hash(value("[2,1]")));
    assert_ne!(
        hash(value("9007199254740992")),
        hash(value("9007199254740993"))
    );
    assert_ne!(hash(value("1")), hash(value(r#""1""#)));
    assert_ne!(hash(V::string("é")), hash(V::string("e\u{301}")));
}

#[test]
fn artifact_versions_have_distinct_record_and_batch_identity() {
    use cdb_core::{admission::*, artifact::*, id::*};
    let make = |version: &str| {
        let bytes = version.as_bytes().to_vec();
        PublishedArtifact::new(
            ArtifactRef::new(
                Iri::new("ctxql:config/test").unwrap(),
                VersionId::new(version).unwrap(),
                ContentHash::of_bytes(&bytes),
            ),
            bytes,
            Limits::default(),
        )
        .unwrap()
    };
    let a = make("1");
    let b = make("2");
    assert_ne!(artifact_key(a.reference()), artifact_key(b.reference()));
    assert_ne!(
        artifact_key(a.reference()),
        resource_key(a.reference().iri().as_str())
    );
    assert!(AdmissionBatch::new(
        vec![],
        vec![],
        vec![],
        vec![a.clone(), b],
        value("{}"),
        Limits::default()
    )
    .is_ok());
    assert!(AdmissionBatch::new(
        vec![],
        vec![],
        vec![],
        vec![a.clone(), a],
        value("{}"),
        Limits::default()
    )
    .is_err());
}

#[test]
fn published_manifest_retains_exact_source_byte_identity() {
    use cdb_core::{artifact::*, id::*};
    let bytes = b"{ \"value\": 1.0 }\n".to_vec();
    let hash = ContentHash::of_bytes(&bytes);
    let artifact = PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new("ctxql:manifest/f").unwrap(),
            VersionId::new("1").unwrap(),
            hash.clone(),
        ),
        bytes,
        Limits::default(),
    )
    .unwrap();
    let manifest = FunctionManifest::from_published(
        ResourceId::new("f").unwrap(),
        &artifact,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(manifest.hash(), &hash);
    assert_ne!(
        manifest.hash(),
        &ContentHash::of_bytes(
            &manifest
                .content()
                .canonical_bytes(Limits::default())
                .unwrap()
        )
    );
}

#[test]
fn policy_projection_retains_normalized_rules() {
    use cdb_core::policy::PolicySet;
    let input = value(
        r#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[
      {"@id":"https://policy.test/p","@type":["https://ns.flur.ee/db#AccessPolicy","https://policy.test/reader"],
       "https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true,
       "https://ns.flur.ee/db#onClass":"https://policy.test/class"}]}"#,
    );
    let policy = PolicySet::from_value(&input).unwrap();
    assert_eq!(PolicySet::from_value(&policy.projection()).unwrap(), policy);
}

#[test]
fn parsed_and_constructed_values_share_container_depth_limits() {
    for depth in 0..=3 {
        let limits = Limits::new(4096, depth, 100, 10000, 4096).unwrap();
        for text in ["null", "[]", "{}", "[[]]", "{\"x\":{}}", "[[[[]]]]"] {
            let value = CanonicalValue::parse(text.as_bytes(), Limits::default()).unwrap();
            assert_eq!(
                CanonicalValue::parse(text.as_bytes(), limits).is_ok(),
                value.canonical_bytes(limits).is_ok(),
                "parse/emit mismatch for {text} at depth {depth}"
            );
        }
    }
}
