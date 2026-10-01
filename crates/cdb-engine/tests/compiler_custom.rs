use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    id::{ContentHash, Iri, VersionId},
    CanonicalValue as V, ErrorKind, Limits, Timestamp,
};
use cdb_engine::{
    compiler::{
        compile, compile_with_compiler_capabilities, load_recorded_plan,
        load_recorded_plan_with_capabilities, CompilerCapabilities, CustomBinding, ExecutablePlan,
        MappingCapabilities, MatchMode, Phase, QuerySource, SelectedProfile,
    },
    options::CompileOptions,
};

const RUNTIME: &str = r#""candidate_order":["depth asc","confidence desc","transaction_time desc","claim_id asc"],"path_ranking":["shorter_path","higher_accumulated_confidence","better_grounding","newer_claims","claim_id_tiebreak"],"cycle_policy":"no_repeated_claim""#;
fn config(numeric: Option<&str>) -> PublishedArtifact {
    let numeric = numeric
        .map(|value| format!(r#", "predicate_numeric":"{value}""#))
        .unwrap_or_default();
    artifact(
        "config",
        &format!(
            r#"{{"name":"fixture","version":"1","runtime":{{{RUNTIME}{numeric}}},"fields":{{}},"external_functions":{{}}}}"#
        ),
    )
}
fn artifact(name: &str, source: &str) -> PublishedArtifact {
    PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new(format!("urn:{name}")).unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(source.as_bytes()),
        ),
        source.as_bytes().to_vec(),
        Limits::default(),
    )
    .unwrap()
}
fn cutoff() -> Timestamp {
    Timestamp::parse("2026-03-31T00:00:00Z").unwrap()
}
fn capabilities() -> CompilerCapabilities {
    CompilerCapabilities {
        custom_predicates: true,
        ..CompilerCapabilities::default()
    }
}
fn query(predicate: &str, bounds: &str) -> String {
    format!(
        r#"{{"about":[{{"from":["A"],"match":"exact"}}],"bounds":{{"max_depth":1{bounds}}},"walk":{{"predicates":[["meta:depth",">",0],{predicate}]}}}}"#
    )
}
fn recorded_plan(
    config_source: &str,
    query_source: &str,
    capabilities: CompilerCapabilities,
) -> ExecutablePlan {
    let query = artifact("recorded-query", query_source);
    compile_with_compiler_capabilities(
        QuerySource::published(&query),
        None,
        &artifact("recorded-config", config_source),
        CompileOptions::default(),
        capabilities,
    )
    .unwrap()
    .finalize(cutoff())
    .unwrap()
}
fn strict_rejects_explicit_accepts(
    plan: &ExecutablePlan,
    capabilities: CompilerCapabilities,
) -> ExecutablePlan {
    let bytes = plan
        .projection()
        .canonical()
        .bytes(Limits::default())
        .unwrap();
    assert_eq!(
        load_recorded_plan(&bytes, plan.hash(), vec![], Limits::default())
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    load_recorded_plan_with_capabilities(
        &bytes,
        plan.hash(),
        vec![],
        Limits::default(),
        capabilities,
    )
    .unwrap()
}
fn compile_custom(source: &str) -> cdb_core::Result<cdb_engine::compiler::ValidatedDraft> {
    compile_with_compiler_capabilities(
        QuerySource::inline(source.as_bytes()),
        None,
        &config(Some("ctxql-predicate-numeric/v2")),
        CompileOptions::default(),
        capabilities(),
    )
}

#[test]
fn compiles_typed_custom_body_with_phase_and_final_index() {
    let source = query(
        r#"{"name":"score","init":{"acc":1,"payload":[null,true]},"bind":{"claim":"meta:confidence","floor":"bound:floor"},"let":{"scaled":"claim * 0.5"},"next":{"acc":"state.acc * scaled"},"keep":"next.acc >= floor"}"#,
        r#", "floor":0.25"#,
    );
    let plan = compile_custom(&source).unwrap().finalize(cutoff()).unwrap();
    let predicate = &plan.walk_predicates()[1];
    assert_eq!(predicate.phase(), Phase::Walk);
    assert_eq!(predicate.index(), 1);
    assert_eq!(predicate.name(), Some("score"));
    let custom = predicate.custom().unwrap();
    assert_eq!(custom.program().keep, "next.acc >= floor");
    assert_eq!(custom.program().lets["scaled"], "claim * 0.5");
    assert!(matches!(
        custom.bindings()["claim"],
        CustomBinding::Field(_, _)
    ));
    assert_eq!(
        custom.bindings()["floor"],
        CustomBinding::Constant(V::parse(b"0.25", Limits::default()).unwrap())
    );
    assert_eq!(custom.binding_names(), vec!["claim", "floor"]);
}

#[test]
fn rejects_missing_or_invalid_bindings_and_keep() {
    for predicate in [
        r#"{"bind":{"x":"bound:missing"},"keep":"true"}"#,
        r#"{"bind":{"x":"not-a-field"},"keep":"true"}"#,
        r#"{"bind":{"x":"meta:depth"},"keep":"   "}"#,
        r#"{"bind":{"x":"meta:depth"},"let":{"x":"1"},"keep":"true"}"#,
    ] {
        assert_eq!(
            compile_custom(&query(predicate, "")).unwrap_err().kind,
            ErrorKind::Invalid,
            "{predicate}"
        );
    }
}

#[test]
fn merge_drop_happens_before_custom_capability_and_preserves_order() {
    let profile = artifact(
        "profile",
        r#"{"name":"p","walk":{"predicates":[{"name":"custom","keep":"true"},{"name":"kept","where":["meta:depth",">",0]}]}}"#,
    );
    let dropped = r#"{"profile":"p","about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1},"walk":{"drop_predicates":["custom"]}}"#;
    let plan = compile(
        QuerySource::inline(dropped.as_bytes()),
        Some(SelectedProfile {
            selector: "p",
            artifact: &profile,
        }),
        &config(None),
        CompileOptions::default(),
    )
    .unwrap()
    .finalize(cutoff())
    .unwrap();
    assert_eq!(plan.walk_predicates()[0].name(), Some("kept"));

    let replaced = r#"{"profile":"p","about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1},"walk":{"predicates":[{"name":"custom","keep":"false"}]}}"#;
    let plan = compile_with_compiler_capabilities(
        QuerySource::inline(replaced.as_bytes()),
        Some(SelectedProfile {
            selector: "p",
            artifact: &profile,
        }),
        &config(Some("ctxql-predicate-numeric/v2")),
        CompileOptions::default(),
        capabilities(),
    )
    .unwrap()
    .finalize(cutoff())
    .unwrap();
    assert_eq!(plan.walk_predicates()[0].name(), Some("custom"));
    assert_eq!(plan.walk_predicates()[0].index(), 0);
    assert_eq!(plan.walk_predicates()[1].name(), Some("kept"));
}

#[test]
fn normalized_reload_preserves_bound_looking_string_as_data() {
    let source = query(
        r#"{"name":"literal","bind":{"x":"bound:value"},"keep":"x == \"bound:other\""}"#,
        r#", "value":"bound:other""#,
    );
    let query_artifact = artifact("query", &source);
    let config = config(Some("ctxql-predicate-numeric/v2"));
    let plan = compile_with_compiler_capabilities(
        QuerySource::published(&query_artifact),
        None,
        &config,
        CompileOptions::default(),
        capabilities(),
    )
    .unwrap()
    .finalize(cutoff())
    .unwrap();
    let bytes = plan
        .projection()
        .canonical()
        .bytes(Limits::default())
        .unwrap();
    assert_eq!(
        load_recorded_plan(&bytes, plan.hash(), vec![], Limits::default())
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    let loaded = load_recorded_plan_with_capabilities(
        &bytes,
        plan.hash(),
        vec![],
        Limits::default(),
        capabilities(),
    )
    .unwrap();
    assert_eq!(loaded.normalized_query(), plan.normalized_query());
    assert_eq!(loaded.hash(), plan.hash());
    assert_eq!(
        loaded.walk_predicates()[1].custom().unwrap().bindings()["x"],
        CustomBinding::Constant(V::string("bound:other"))
    );
}

#[test]
fn recorded_external_functions_require_the_explicit_capability() {
    let manifest_hash = ContentHash::of_bytes(b"manifest");
    let config = format!(
        r#"{{"name":"external","version":"1","runtime":{{{RUNTIME}}},"fields":{{}},"external_functions":{{"test/function":{{"version":"1","manifest_uri":"urn:function:test","manifest_hash":"{}","deterministic":true}}}}}}"#,
        manifest_hash.as_str()
    );
    let plan = recorded_plan(
        &config,
        r#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1}}"#,
        CompilerCapabilities::default(),
    );
    let loaded = strict_rejects_explicit_accepts(
        &plan,
        CompilerCapabilities {
            external_functions: true,
            ..Default::default()
        },
    );
    assert_eq!(loaded.hash(), plan.hash());
}

#[test]
fn recorded_prepared_interpretation_requires_the_explicit_capability() {
    let mapping_hash = ContentHash::of_bytes(b"mapping");
    let config = format!(
        r#"{{"name":"prepared","version":"1","runtime":{{{RUNTIME}}},"fields":{{}},"external_functions":{{}},"preparation":[{{"source_id":"source","provider_version":"1","mapping_ref":{{"iri":"urn:mapping:test","version":"1","hash":"{}"}},"mode":"live","capabilities":[],"selection":{{}},"limits":{{}}}}]}}"#,
        mapping_hash.as_str()
    );
    let plan = recorded_plan(
        &config,
        r#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1}}"#,
        CompilerCapabilities::default(),
    );
    let loaded = strict_rejects_explicit_accepts(
        &plan,
        CompilerCapabilities {
            prepared_interpretation: true,
            ..Default::default()
        },
    );
    assert_eq!(loaded.hash(), plan.hash());
}

#[test]
fn recorded_approximate_landing_restores_mode_with_explicit_capability() {
    let (major, minor, patch) = cdb_engine::lexical::UNICODE_VERSION;
    let config = format!(
        r#"{{"name":"landing","version":"1","runtime":{{{RUNTIME}}},"fields":{{}},"external_functions":{{}},"landing":{{"resolver":"ctxql.lexical-token-overlap/v1","unicode_version":[{major},{minor},{patch}],"minimum_overlap":1}}}}"#
    );
    let plan = recorded_plan(
        &config,
        r#"{"about":[{"from":["Acme supplier"],"match":"approximate"}],"bounds":{"max_depth":1}}"#,
        CompilerCapabilities {
            mappings: MappingCapabilities {
                lexical_landing: true,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    let loaded = strict_rejects_explicit_accepts(
        &plan,
        CompilerCapabilities {
            approximate_landing: true,
            ..Default::default()
        },
    );
    assert_eq!(loaded.blocks()[0].match_mode(), MatchMode::Approximate);
    assert_eq!(loaded.hash(), plan.hash());
}

#[test]
fn custom_requires_explicit_numeric_abi_while_old_builtins_remain_compatible() {
    let custom = query(r#"{"keep":"true"}"#, "");
    assert_eq!(
        compile_with_compiler_capabilities(
            QuerySource::inline(custom.as_bytes()),
            None,
            &config(None),
            CompileOptions::default(),
            capabilities(),
        )
        .unwrap_err()
        .kind,
        ErrorKind::Unsupported
    );
    assert_eq!(
        compile(
            QuerySource::inline(custom.as_bytes()),
            None,
            &config(Some("ctxql-predicate-numeric/v2")),
            CompileOptions::default(),
        )
        .unwrap_err()
        .kind,
        ErrorKind::Unsupported
    );
    let builtin = query(r#"["meta:depth","<",2]"#, "");
    assert!(compile(
        QuerySource::inline(builtin.as_bytes()),
        None,
        &config(None),
        CompileOptions::default(),
    )
    .is_ok());
    assert_eq!(
        compile(
            QuerySource::inline(builtin.as_bytes()),
            None,
            &config(Some("ctxql-predicate-numeric/v1")),
            CompileOptions::default(),
        )
        .unwrap_err()
        .kind,
        ErrorKind::Invalid
    );
}
