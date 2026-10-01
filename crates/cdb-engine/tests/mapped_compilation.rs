use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    id::{ContentHash, Iri, VersionId},
    CanonicalValue as V, ErrorKind, Limits, Timestamp,
};
use cdb_engine::{compiler::*, options::CompileOptions};
const CONFIG: &str = r#"{"name":"mapped","version":"1","runtime":{"candidate_order":["depth asc","confidence desc","transaction_time desc","claim_id asc"],"path_ranking":["shorter_path","higher_accumulated_confidence","better_grounding","newer_claims","claim_id_tiebreak"],"cycle_policy":"no_repeated_claim"},"fields":{"meta:ext:x":{"source":"stored_predicate","iri":"ex:p"},"meta:ext:unused":{"source":"reasoned","iri":"ex:unused"}},"external_functions":{}}"#;
const QUERY: &str = r#"{"@context":{"ex":"https://example.org/"},"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1,"raw":"ex:literal"},"walk":{"predicates":[["meta:ext:x","=","ex:literal"]]}}"#;
fn config(text: &str) -> PublishedArtifact {
    PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new("urn:config").unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(text.as_bytes()),
        ),
        text.as_bytes().to_vec(),
        Limits::default(),
    )
    .unwrap()
}
#[test]
fn explicit_capability_and_position_local_normalization() {
    let c = config(CONFIG);
    assert_eq!(
        compile(
            QuerySource::inline(QUERY.as_bytes()),
            None,
            &c,
            CompileOptions::default()
        )
        .unwrap_err()
        .kind,
        ErrorKind::Unsupported
    );
    let plan = compile_with_capabilities(
        QuerySource::inline(QUERY.as_bytes()),
        None,
        &c,
        CompileOptions::default(),
        MappingCapabilities {
            stored_predicate: true,
            ..MappingCapabilities::default()
        },
    )
    .unwrap()
    .finalize(Timestamp::parse("2026-04-01T00:00:00Z").unwrap())
    .unwrap();
    assert_eq!(
        plan.walk_predicates()[0].mapping().unwrap().iri().as_str(),
        "https://example.org/p"
    );
    assert_eq!(
        plan.walk_predicates()[0].builtin().unwrap().operand(),
        &cdb_engine::values::Value::String("ex:literal".into())
    );
    assert_eq!(
        plan.normalized_query()
            .field("bounds")
            .unwrap()
            .field("raw")
            .unwrap(),
        &V::string("ex:literal")
    );
    assert_eq!(
        plan.semantic_config()
            .field("fields")
            .unwrap()
            .field("meta:ext:unused")
            .unwrap()
            .field("iri")
            .unwrap(),
        &V::string("https://example.org/unused")
    );
    assert_eq!(
        plan.projection()
            .canonical()
            .payload()
            .field("artifacts")
            .unwrap()
            .field("config")
            .unwrap(),
        &c.reference().projection()
    );
    assert_eq!(c.content(), CONFIG.as_bytes());
}
#[test]
fn reasoned_and_computed_are_not_enabled() {
    for mapping in [
        r#"{"source":"reasoned","iri":"ex:p"}"#,
        r#"{"source":"computed","resolver":"local"}"#,
    ] {
        let text = CONFIG.replace(r#"{"source":"stored_predicate","iri":"ex:p"}"#, mapping);
        assert_eq!(
            compile_with_capabilities(
                QuerySource::inline(QUERY.as_bytes()),
                None,
                &config(&text),
                CompileOptions::default(),
                MappingCapabilities {
                    stored_predicate: true,
                    ..MappingCapabilities::default()
                }
            )
            .unwrap_err()
            .kind,
            ErrorKind::Unsupported
        );
    }
}
