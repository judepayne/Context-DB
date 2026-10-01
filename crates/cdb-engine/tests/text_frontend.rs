use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    id::{ContentHash, Iri, VersionId},
    CanonicalValue as V, Limits, Timestamp,
};
use cdb_engine::{
    artifacts::{ArtifactKind as K, ArtifactName, Catalog, CatalogOptions},
    compiler::{compile, compile_with_source_origins, MappingCapabilities, QuerySource},
    frontend::{parse, parse_detailed, SourceRole},
    options::CompileOptions,
};

const CONFIG: &str = r#"{"name":"fixture","version":"1","runtime":{"candidate_order":["depth asc","confidence desc","transaction_time desc","claim_id asc"],"path_ranking":["shorter_path","higher_accumulated_confidence","better_grounding","newer_claims","claim_id_tiebreak"],"cycle_policy":"no_repeated_claim"},"fields":{},"external_functions":{}}"#;
fn published(name: &str, bytes: &str) -> PublishedArtifact {
    PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new(format!("urn:{name}")).unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(bytes.as_bytes()),
        ),
        bytes.as_bytes().to_vec(),
        Limits::default(),
    )
    .unwrap()
}
fn query(s: &str) -> V {
    parse(K::Query, s.as_bytes(), Limits::default())
        .unwrap()
        .value
}
#[test]
fn complete_clause_parity_and_native_program_preservation() {
    let text = r#"QUERY
USE PROFILE bank/risk-default
CONTEXT
  bank = "https://bank.example/ontology/"
ABOUT
  FROM "Acme Unicode λ" TO ["Vendor X", "Vendor Y"] MATCH approximate
  FROM ["https://example/x", "bank:y"] MATCH exact
BOUNDS
  max_depth = 4
  min_confidence = 0.25000000000000000000000000001
  meta:ext:role = bank:RiskAnalyst
WALK outgoing
  DROP PREDICATES ["old"]
  WHERE
    meta:confidence >= bound:min_confidence
  PREDICATE named
    WHERE
      meta:relation_type subproperty_of bank:supplies
  PREDICATE accumulated
    INIT
      acc = 1.0
      payload = {"null": null, "array": [true, 123456789012345678901234567890]}
    BIND
      claim = meta:confidence
      floor = bound:meta:ext:role
    LET
      score = { let x = 1.0 / 3.0; x } // native Decimal, unchanged
    NEXT
      acc = state.acc * claim
    KEEP next.acc >= 0.1 && "https://x/#λ" != "" // preserved
FILTER
  WHERE
    path.meta:claim_type contains_isa bank:Decision
RETURN
  claims
  paths = false
  evidence = true
  explain = false
"#;
    let json = r#"{"profile":"bank/risk-default","@context":{"bank":"https://bank.example/ontology/"},"about":[{"from":["Acme Unicode λ"],"to":["Vendor X","Vendor Y"],"match":"approximate"},{"from":["https://example/x","bank:y"],"match":"exact"}],"bounds":{"max_depth":4,"min_confidence":0.25000000000000000000000000001,"meta:ext:role":"bank:RiskAnalyst"},"walk":{"direction":"outgoing","drop_predicates":["old"],"predicates":[["meta:confidence",">=","bound:min_confidence"],{"name":"named","where":["meta:relation_type","subproperty_of","bank:supplies"]},{"name":"accumulated","init":{"acc":1.0,"payload":{"null":null,"array":[true,123456789012345678901234567890]}},"bind":{"claim":"meta:confidence","floor":"bound:meta:ext:role"},"let":{"score":"{ let x = 1.0 / 3.0; x } // native Decimal, unchanged"},"next":{"acc":"state.acc * claim"},"keep":"next.acc >= 0.1 && \"https://x/#λ\" != \"\" // preserved"}]},"filter":{"predicates":[["path.meta:claim_type","contains_isa","bank:Decision"]]},"return":{"claims":true,"paths":false,"evidence":true,"explain":false}}"#;
    assert_eq!(query(text), query(json));
    for newline in ["\n", "\r\n", "\r"] {
        assert_eq!(
            query(&format!(
                "\u{feff}# header{newline}{}",
                text.replace('\n', newline)
            )),
            query(json)
        );
    }
}
#[test]
fn profiles_clear_comments_and_source_offsets() {
    let text =
        "\u{feff}// header\r\nPROFILE\r\nNAME bank/risk-default\r\nWALK\r\n  PREDICATES []\r\n";
    let p = parse(K::Profile, text.as_bytes(), Limits::default()).unwrap();
    assert_eq!(
        p.value.field("name").unwrap().as_str().unwrap(),
        "bank/risk-default"
    );
    let span = p.source_map.span("/name").unwrap();
    assert_eq!(&text[span.start..span.end], "NAME bank/risk-default");
    assert_eq!(p.source_map.location(span.start), Some((3, 1)));
    let json = "\u{feff}{\"bounds\": {\"x/y\": 123}, \"return\": {\"claims\": false}}";
    let p = parse(K::Query, json.as_bytes(), Limits::default()).unwrap();
    let span = p.source_map.span("/bounds/x~1y").unwrap();
    assert_eq!(&json[span.start..span.end], "123");
}
#[test]
fn rejects_malformed_duplicate_and_mixed_structures() {
    for s in [
        "{\"bounds\": QUERY",
        "{\"bounds\":{},\"bounds\":{}}",
        "query\n",
        "QUERY\nNAME x",
        "PROFILE\nNAME x",
        "QUERY\nBOUNDS\n   x = 1",
        "QUERY\nBOUNDS\n\tx = 1",
        "QUERY\nBOUNDS\n  x = 1\n  x = 2",
        "QUERY\nRETURN\n  claims = 1",
        "QUERY\nRETURN\n  unknown",
        "QUERY\nABOUT\n  FROM \"x\" TO \"y\" TO \"z\"",
        "QUERY\nWALK\n  PREDICATES []\n  WHERE\n    meta:x = 1",
        "QUERY\nWALK\n  PREDICATE p\n    INIT\n      x = state.x",
        "QUERY\nWALK\n  PREDICATE p\n    KEEP true\n    KEEP false",
        "QUERY\nWALK\n  PREDICATE p\n    WHERE\n      meta:x = 1\n    KEEP true",
        "QUERY\nWALK\n  PREDICATE p\n    KEEP true\n  PREDICATE p\n    KEEP true",
        "QUERY\nBOUNDS\n  x = [1,]",
        "QUERY\nUSE PROFILE ../escape",
        "QUERY\nFILTER\n  PREDICATE p\n    BIND\n      x = 1\n    KEEP true",
    ] {
        assert!(
            parse(K::Query, s.as_bytes(), Limits::default()).is_err(),
            "accepted {s}"
        );
    }
    assert!(parse(K::Config, b"QUERY", Limits::default()).is_err());
}
#[test]
fn budgets_and_json_losslessness() {
    assert_eq!(
        query("{\"bounds\":{\"n\":1e100}}"),
        query("QUERY\nBOUNDS\n  n = 1e100")
    );
    for limits in [
        Limits::new(0, 64, 100, 1000, 1000).unwrap(),
        Limits::new(1000, 0, 100, 1000, 1000).unwrap(),
        Limits::new(1000, 64, 0, 1000, 1000).unwrap(),
        Limits::new(1000, 64, 100, 0, 1000).unwrap(),
        Limits::new(1000, 64, 100, 1000, 0).unwrap(),
    ] {
        assert!(parse(K::Query, b"QUERY\nBOUNDS\n  n = 1", limits).is_err());
    }
}

#[test]
fn compiler_catalog_provenance_and_detailed_errors() {
    let json = r#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1}}"#;
    let text = "QUERY\nABOUT\n  FROM A MATCH exact\nBOUNDS\n  max_depth = 1\n";
    let config = published("config", CONFIG);
    let cutoff = Timestamp::parse("2026-03-31T00:00:00Z").unwrap();
    let inline_json = compile(
        QuerySource::inline(json.as_bytes()),
        None,
        &config,
        CompileOptions::default(),
    )
    .unwrap()
    .finalize(cutoff)
    .unwrap();
    let inline_text = compile(
        QuerySource::inline(text.as_bytes()),
        None,
        &config,
        CompileOptions::default(),
    )
    .unwrap()
    .finalize(cutoff)
    .unwrap();
    assert_eq!(inline_json.projection(), inline_text.projection());
    assert_eq!(inline_json.hash(), inline_text.hash());

    let jq = published("query", json);
    let tq = published("query", text);
    let jp = compile(
        QuerySource::published(&jq),
        None,
        &config,
        CompileOptions::default(),
    )
    .unwrap()
    .finalize(cutoff)
    .unwrap();
    let tp = compile(
        QuerySource::published(&tq),
        None,
        &config,
        CompileOptions::default(),
    )
    .unwrap()
    .finalize(cutoff)
    .unwrap();
    assert_ne!(jq.reference().hash(), tq.reference().hash());
    assert_ne!(jp.hash(), tp.hash());

    let (_, origins) = compile_with_source_origins(
        QuerySource::inline(text.as_bytes()),
        None,
        &config,
        CompileOptions::default(),
        MappingCapabilities::default(),
    )
    .unwrap();
    let origin = origins.merged("/bounds/max_depth").unwrap();
    assert_eq!(origin.role, SourceRole::Query);
    assert_eq!(origin.line, 5);

    let entries = [(K::Query, ArtifactName::new("native", 100).unwrap(), tq)];
    assert_eq!(
        Catalog::new(
            entries,
            CatalogOptions {
                limits: Limits::default(),
                max_entries: 2,
                max_name_bytes: 100,
                max_retained_bytes: 100_000,
            }
        )
        .unwrap()
        .len(),
        1
    );

    let error = parse_detailed(K::Query, b"{\r\n QUERY", Limits::default()).unwrap_err();
    assert_eq!(error.diagnostic.source_role, SourceRole::Query);
    assert!(error.diagnostic.span.end <= 9);
    assert!(error.diagnostic.line >= 1 && error.diagnostic.column >= 1);
    assert!(parse(K::Query, b"{ QUERY\nABOUT\n", Limits::default()).is_err());
}
