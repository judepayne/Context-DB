use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    id::{ContentHash, Iri, VersionId},
    Limits, Timestamp,
};
use cdb_engine::{compiler::*, options::CompileOptions, values::Operator};

fn artifact(bytes: &[u8]) -> PublishedArtifact {
    PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new("urn:config:interpretation").unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(bytes),
        ),
        bytes.to_vec(),
        Limits::default(),
    )
    .unwrap()
}

#[test]
fn six_operators_and_three_mapping_descriptors_are_typed() {
    let config = format!(
        r#"{{"name":"interpretation","version":"1","runtime":{{"candidate_order":["depth asc","confidence desc","transaction_time desc","claim_id asc"],"path_ranking":["shorter_path","higher_accumulated_confidence","better_grounding","newer_claims","claim_id_tiebreak"],"cycle_policy":"no_repeated_claim"}},"fields":{{"meta:ext:stored":{{"source":"stored_predicate","iri":"urn:p:stored"}},"meta:ext:reasoned":{{"source":"reasoned","iri":"urn:p:reasoned","requires":["reasoner"]}},"meta:ext:computed":{{"source":"computed","iri":"urn:p:reasoned","resolver":{{"iri":"urn:resolver:count","version":"1","hash":"{}"}},"requires":["reasoner"]}}}},"external_functions":{{}}}}"#,
        ContentHash::of_bytes(b"ctxql-local-count/v1").as_str()
    );
    let query = br#"{"about":[{"from":["urn:A"],"match":"exact"}],"bounds":{"max_depth":1},"walk":{"predicates":[["meta:claim_type","isa","urn:Top"],["meta:subject_type","not_isa","urn:Hidden"],["meta:relation_type","subproperty_of","urn:p"],["meta:relation","not_subproperty_of","urn:q"],["meta:ext:stored","contains","urn:value"],["meta:ext:reasoned","exists",true],["meta:ext:computed","exists",true]]},"filter":{"predicates":[["path.meta:claim_type","contains_isa","urn:Top"],["path.meta:relation_type","contains_subproperty_of","urn:p"]]}}"#;
    let config = artifact(config.as_bytes());
    let plan = compile_with_compiler_capabilities(
        QuerySource::inline(query),
        None,
        &config,
        CompileOptions::default(),
        CompilerCapabilities {
            mappings: MappingCapabilities {
                stored_predicate: true,
                reasoned: true,
                computed: true,
                ontology: true,
                lexical_landing: false,
            },
            custom_predicates: false,
            external_functions: false,
            prepared_interpretation: false,
            approximate_landing: false,
        },
    )
    .unwrap()
    .finalize(Timestamp::parse("2026-01-01T00:00:00Z").unwrap())
    .unwrap();
    assert_eq!(
        plan.walk_predicates()[0].builtin().unwrap().operator(),
        Operator::Isa
    );
    assert_eq!(
        plan.filter_predicates()[0].builtin().unwrap().operator(),
        Operator::ContainsIsa
    );
    assert!(matches!(
        plan.walk_predicates()[4].mapping().unwrap(),
        FieldMapping::StoredPredicate { .. }
    ));
    assert!(matches!(
        plan.walk_predicates()[5].mapping().unwrap(),
        FieldMapping::Reasoned { .. }
    ));
    assert!(matches!(
        plan.walk_predicates()[6].mapping().unwrap(),
        FieldMapping::Computed { .. }
    ));
}

#[test]
fn approximate_landing_binds_resolver_unicode_and_threshold() {
    let (major, minor, patch) = cdb_engine::lexical::UNICODE_VERSION;
    let config = artifact(
        format!(r#"{{"name":"lexical","version":"1","runtime":{{"candidate_order":["depth asc","confidence desc","transaction_time desc","claim_id asc"],"path_ranking":["shorter_path","higher_accumulated_confidence","better_grounding","newer_claims","claim_id_tiebreak"],"cycle_policy":"no_repeated_claim"}},"fields":{{}},"external_functions":{{}},"landing":{{"resolver":"ctxql.lexical-token-overlap/v1","unicode_version":[{major},{minor},{patch}],"minimum_overlap":1}}}}"#).as_bytes(),
    );
    let query =
        br#"{"about":[{"from":["Acme supplier"],"match":"approximate"}],"bounds":{"max_depth":1}}"#;
    let plan = compile_with_capabilities(
        QuerySource::inline(query),
        None,
        &config,
        CompileOptions::default(),
        MappingCapabilities {
            lexical_landing: true,
            ..Default::default()
        },
    )
    .unwrap()
    .finalize(Timestamp::parse("2026-01-01T00:00:00Z").unwrap())
    .unwrap();
    assert_eq!(plan.blocks()[0].match_mode(), MatchMode::Approximate);
}
