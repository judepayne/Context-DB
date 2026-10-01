use cdb_core::{CanonicalValue as V, ErrorKind, Limits};
use cdb_engine::{compiler::*, execution::*, options::CompileOptions};
use cdb_testkit::reference_fixture::*;

fn lexical_config() -> cdb_core::artifact::PublishedArtifact {
    let (major, minor, patch) = cdb_engine::lexical::UNICODE_VERSION;
    artifact(
        "urn:config:lexical",
        format!(r#"{{"name":"lexical","version":"1","runtime":{{"candidate_order":["depth asc","confidence desc","transaction_time desc","claim_id asc"],"path_ranking":["shorter_path","higher_accumulated_confidence","better_grounding","newer_claims","claim_id_tiebreak"],"cycle_policy":"no_repeated_claim"}},"fields":{{}},"external_functions":{{}},"landing":{{"resolver":"ctxql.lexical-token-overlap/v1","unicode_version":[{major},{minor},{patch}],"minimum_overlap":1}}}}"#).as_bytes(),
    ).unwrap()
}

fn draft(config: &cdb_core::artifact::PublishedArtifact, seed_limit: u64) -> ValidatedDraft {
    let query = format!(
        r#"{{"about":[{{"from":["supplier"],"match":"approximate"}}],"bounds":{{"max_depth":1,"seed_limit":{seed_limit}}},"return":{{"explain":true}}}}"#
    );
    compile_with_capabilities(
        QuerySource::inline(query.as_bytes()),
        None,
        config,
        CompileOptions::default(),
        MappingCapabilities {
            lexical_landing: true,
            ..Default::default()
        },
    )
    .unwrap()
}

async fn run(fixture: &ReferenceFixture, draft: ValidatedDraft) -> cdb_core::Result<V> {
    let mut bytes = vec![];
    execute(
        draft,
        &fixture.backend,
        &fixture.backend,
        &fixture.principal,
        fixture,
        ExecutionOptions::default(),
        &mut |value| {
            bytes.extend_from_slice(value);
            Ok(())
        },
    )
    .await?;
    V::parse(&bytes, Limits::default())
}

#[tokio::test]
async fn authorized_projection_catalog_ranks_by_score_then_id_and_zero_still_checks_scope() {
    let config = lexical_config();
    let mut builder = FixtureBuilder::new();
    builder.artifact(config.clone());
    builder.entity("urn:A", Some("supplier alpha")).unwrap();
    builder.entity("urn:B", Some("supplier beta")).unwrap();
    let fixture = builder.build().await.unwrap();

    let response = run(&fixture, draft(&config, 2)).await.unwrap();
    let seeds = response
        .field("explain")
        .unwrap()
        .field("seeds")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(seeds.len(), 2);
    assert_eq!(seeds[0].field("id").unwrap(), &V::string("urn:A"));
    assert_eq!(seeds[1].field("id").unwrap(), &V::string("urn:B"));
    assert_eq!(
        run(&fixture, draft(&config, 0))
            .await
            .unwrap()
            .field("explain")
            .unwrap()
            .field("seeds")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        0
    );

    let mut policy = allow_policy()
        .unwrap()
        .projection()
        .as_object()
        .unwrap()
        .clone();
    let mut rules = policy["policies"].as_array().unwrap().to_vec();
    rules.push(V::parse(
        format!(r#"{{"@id":"https://fixture.example/deny-label","@type":["https://ns.flur.ee/db#AccessPolicy","https://fixture.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":false,"https://ns.flur.ee/db#onProperty":"{}"}}"#, property_iri("label").unwrap().as_str()).as_bytes(),
        Limits::default(),
    ).unwrap());
    policy.insert("policies".into(), V::Array(rules));
    fixture
        .backend
        .set_policy(cdb_core::policy::PolicySet::from_value(&V::Object(policy)).unwrap())
        .unwrap();
    assert_eq!(
        run(&fixture, draft(&config, 0)).await.unwrap_err().kind,
        ErrorKind::Denied
    );
}
