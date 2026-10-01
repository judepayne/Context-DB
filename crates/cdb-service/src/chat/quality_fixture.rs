use super::*;
use crate::{
    acquisition::{AcquisitionService, AdmissionContext, WaitPoint},
    acquisition_v2_fixture::AcquisitionV2Fixture,
    ingest::{ingest, IngestMode, IngestWait, OntologyMode},
    source_target::SourceTarget,
};
use cdb_backend_fluree::{
    semantic::FlureeSemanticLedger,
    semantic_preparation::{prepare_historical_authorized_view, ExtractionLimits},
};
use cdb_core::{
    claim::CandidateClaim,
    id::{AttemptId, BundleId, ContentHash, ExtractionRunId, JobId},
    semantic_admission::{stable_acquisition_v2_claim_id, ValidatedSemanticBundle},
    CanonicalValue as V, Limits, Timestamp,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    sync::{atomic::AtomicBool, Arc},
};

pub(super) const QUALITY_QUOTE: &str =
    "permits further drawings while no Event of Default is continuing";
const LABEL: &str = "http://www.w3.org/2000/01/rdf-schema#label";
const PROVISION: &str = "urn:ctxql:chat-quality:permitsFurtherDrawings";

pub(super) struct QualityFixture {
    pub fixture: AcquisitionV2Fixture,
    pub scenario: Value,
    pub provision_subject: String,
    pub provision_ingest_report: Value,
    pub denied_claim_ids: Vec<String>,
    pub privileged_denied_claims_present: bool,
}

fn literal_claim(component: &str, subject: &str, predicate: &str, lexical: &str) -> CandidateClaim {
    let mut value = V::parse(
        br#"{"claim_id":"urn:ctxql:claim:v2:placeholder","claim_type":"urn:type:claim","confidence":1,"ext":{"ctxql.acquisition.v2/claim_identity":"stable-component/v1","ctxql.acquisition.v2/component_ref":"placeholder"},"grounding_level":"source_lineage_available","lineage":{"schema":"ctxql.lineage.v1","sources":[{"source_id":"urn:source:chat-quality","kind":"document","uri":"urn:evidence:chat-quality"}]},"object_id":{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#string","value":"placeholder","language":null},"object_type":"http://www.w3.org/2001/XMLSchema#string","relation":"urn:predicate:placeholder","relation_type":"urn:type:relation","subject_id":"urn:subject:placeholder","subject_type":"urn:type:entity"}"#,
        Limits::default(),
    ).unwrap();
    let V::Object(fields) = &mut value else {
        unreachable!()
    };
    fields.insert("subject_id".into(), V::string(subject));
    fields.insert("relation".into(), V::string(predicate));
    let V::Object(object) = fields.get_mut("object_id").unwrap() else {
        unreachable!()
    };
    object.insert("value".into(), V::string(lexical));
    let V::Object(ext) = fields.get_mut("ext").unwrap() else {
        unreachable!()
    };
    ext.insert(
        "ctxql.acquisition.v2/component_ref".into(),
        V::string(component),
    );
    reseal(value)
}

fn fixture_claim(spec: &Value) -> CandidateClaim {
    if spec["object"]["kind"] == "literal" {
        return literal_claim(
            spec["component"].as_str().unwrap(),
            spec["subject"].as_str().unwrap(),
            spec["predicate"].as_str().unwrap(),
            spec["object"]["value"].as_str().unwrap(),
        );
    }
    let mut value = V::parse(
        br#"{"claim_id":"urn:ctxql:claim:v2:placeholder","claim_type":"urn:type:claim","confidence":1,"ext":{"ctxql.acquisition.v2/claim_identity":"stable-component/v1","ctxql.acquisition.v2/component_ref":"placeholder"},"grounding_level":"source_lineage_available","lineage":{"schema":"ctxql.lineage.v1","sources":[{"source_id":"urn:source:chat-quality","kind":"document","uri":"urn:evidence:chat-quality"}]},"object_id":"urn:object:placeholder","object_type":"urn:type:entity","relation":"urn:predicate:placeholder","relation_type":"urn:type:relation","subject_id":"urn:subject:placeholder","subject_type":"urn:type:entity"}"#,
        Limits::default(),
    ).unwrap();
    let V::Object(fields) = &mut value else {
        unreachable!()
    };
    fields.insert(
        "subject_id".into(),
        V::string(spec["subject"].as_str().unwrap()),
    );
    fields.insert(
        "relation".into(),
        V::string(spec["predicate"].as_str().unwrap()),
    );
    fields.insert(
        "object_id".into(),
        V::string(spec["object"]["value"].as_str().unwrap()),
    );
    let V::Object(ext) = fields.get_mut("ext").unwrap() else {
        unreachable!()
    };
    ext.insert(
        "ctxql.acquisition.v2/component_ref".into(),
        V::string(spec["component"].as_str().unwrap()),
    );
    reseal(value)
}

fn reseal(mut value: V) -> CandidateClaim {
    let provisional = CandidateClaim::from_value(&value).unwrap();
    let id = stable_acquisition_v2_claim_id(&provisional, Limits::default()).unwrap();
    let V::Object(fields) = &mut value else {
        unreachable!()
    };
    fields.insert("claim_id".into(), V::string(id.as_str()));
    CandidateClaim::from_value(&value).unwrap()
}

async fn trusted_admit(fixture: &AcquisitionV2Fixture, claims: Vec<CandidateClaim>, suffix: &str) {
    let acquisition = AcquisitionService::open(
        &fixture.config().unwrap(),
        fixture.catalog_identity().clone(),
    )
    .await
    .unwrap();
    let capture = acquisition
        .semantic_writer
        .session()
        .await
        .capture_current()
        .await
        .unwrap();
    let bundle = ValidatedSemanticBundle::new(
        BundleId::new(format!("bundle:{suffix}")).unwrap(),
        ExtractionRunId::new(format!("extraction:{suffix}")).unwrap(),
        capture,
        V::object([
            (
                "schema".into(),
                V::string("ctxql-extraction-admission-descriptor/v2"),
            ),
            (
                "evaluation_id".into(),
                V::string(format!("evaluation:{suffix}")),
            ),
            (
                "review_payload_root".into(),
                V::string(ContentHash::of_bytes(suffix.as_bytes()).as_str()),
            ),
            ("ontology_mode".into(), V::string("direct")),
        ])
        .unwrap(),
        claims
            .into_iter()
            .enumerate()
            .map(|(index, claim)| (format!("{suffix}:{index}"), claim))
            .collect(),
        Limits::default(),
    )
    .unwrap();
    acquisition
        .admit_foreground(
            JobId::new(format!("job:{suffix}")).unwrap(),
            AttemptId::new(format!("attempt:{suffix}")).unwrap(),
            &bundle,
            ContentHash::of_bytes(format!("{suffix} selectors").as_bytes()),
            V::object([]).unwrap(),
            Timestamp::from_millis(1).unwrap(),
            WaitPoint::Projected,
            AdmissionContext::NoGraph,
        )
        .await
        .unwrap();
    acquisition.shutdown().await.unwrap();
}

pub(super) async fn setup_quality_fixture() -> QualityFixture {
    let scenario: Value = serde_json::from_str(include_str!(
        "../../../../fixtures/conformance/chat/quality-scenarios-v1.json"
    ))
    .unwrap();
    let specifications = scenario["claims"].as_array().unwrap();
    let synthetic = specifications
        .iter()
        .filter(|claim| claim["component"] != "quality#provision")
        .map(fixture_claim)
        .collect::<Vec<_>>();
    let denied_claim_ids = specifications
        .iter()
        .filter(|claim| {
            matches!(
                claim["component"].as_str(),
                Some("quality#hidden-label" | "quality#hidden-lender")
            )
        })
        .map(fixture_claim)
        .map(|claim| claim.id().as_str().to_owned())
        .collect::<Vec<_>>();
    let fixture = AcquisitionV2Fixture::create_with_semantic_denials(&denied_claim_ids)
        .await
        .unwrap();
    trusted_admit(&fixture, synthetic, "chat-quality-base").await;

    let source = fixture
        .write_document(
            "quality-provision-source.txt",
            format!("Atlas Facility was executed on 2022-12-06 and {QUALITY_QUOTE}.\n").as_bytes(),
        )
        .unwrap();
    fixture.set_pi_response(&format!(
        "ENTITY:\nId: agreement\nName: Atlas Facility\nKnown entity: none\nEVIDENCE:\nRange: {{{{LINE_RANGE_1}}}}\nOccurrence: 0\nQuote: Atlas Facility\n---\nCLAIM:\nKind: attribute\nSubject: local agreement\nPredicate: urn:ctxql:a2:executedOn\nPredicate note: Fixture source-witness scaffold\nPredicate selected: 0\nValue: 2022-12-06\nDatatype: http://www.w3.org/2001/XMLSchema#date\nDatatype note: Complete calendar date\nDatatype selected: 0\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note: The complete source line is retained as evidence.\nEVIDENCE:\nRange: {{{{LINE_RANGE_1}}}}\nOccurrence: 0\nQuote: Atlas Facility was executed on 2022-12-06 and {QUALITY_QUOTE}.\n---"
    )).unwrap();
    let report = ingest(
        fixture.config().unwrap(),
        SourceTarget::LocalFile(source),
        IngestMode::Admit(IngestWait::Projected),
        OntologyMode::Hard,
        2 * 1024 * 1024,
        None,
        None,
        None,
        cdb_provider_pi::cancel::CancellationToken::default(),
    )
    .await
    .unwrap();
    let provision_ingest_report = serde_json::to_value(report).unwrap();
    let scaffold = provision_ingest_report["documents"][0]["admitted_claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|claim| claim["relation"] == "urn:ctxql:a2:executedOn")
        .unwrap_or_else(|| panic!("admitted source-witness scaffold: {provision_ingest_report:#}"));
    let mut provision =
        V::parse(&serde_json::to_vec(scaffold).unwrap(), Limits::default()).unwrap();
    let V::Object(fields) = &mut provision else {
        unreachable!()
    };
    let provision_subject = scenario["entities"]["agreement"]
        .as_str()
        .unwrap()
        .to_owned();
    fields.insert(
        "claim_id".into(),
        V::string("urn:ctxql:claim:v2:placeholder"),
    );
    fields.insert("subject_id".into(), V::string(&provision_subject));
    fields.insert("relation".into(), V::string(PROVISION));
    fields.insert("relation_type".into(), V::string("urn:type:relation"));
    fields.insert(
        "object_type".into(),
        V::string("http://www.w3.org/2001/XMLSchema#string"),
    );
    fields.insert(
        "object_id".into(),
        V::object([
            ("kind".into(), V::string("literal")),
            (
                "datatype".into(),
                V::string("http://www.w3.org/2001/XMLSchema#string"),
            ),
            (
                "value".into(),
                V::string(
                    "Further drawings are permitted while no Event of Default is continuing.",
                ),
            ),
            ("language".into(), V::Null),
        ])
        .unwrap(),
    );
    let V::Object(ext) = fields.get_mut("ext").unwrap() else {
        unreachable!()
    };
    ext.insert(
        "ctxql.acquisition.v2/component_ref".into(),
        V::string("quality#provision"),
    );
    trusted_admit(&fixture, vec![reseal(provision)], "chat-quality-provision").await;

    // A principal outside the fixture's PublicPolicy class sees both denied
    // claims, proving reader-side absence is policy filtering rather than setup omission.
    let config = fixture.config().unwrap();
    let (semantic_path, semantic_options) = config.semantic_binding().unwrap();
    let semantic = FlureeSemanticLedger::open_file(semantic_path, semantic_options)
        .await
        .unwrap();
    let capture = semantic.capture_current(None).await.unwrap();
    let privileged = prepare_historical_authorized_view(
        &semantic,
        &capture,
        "urn:ctxql:quality-fixture-auditor",
        "ctxql:query",
        ExtractionLimits::default(),
    )
    .await
    .unwrap();
    let privileged_ids = privileged
        .authorized_claims
        .iter()
        .filter_map(|record| record.claim().map(|claim| claim.id().as_str().to_owned()))
        .collect::<BTreeSet<_>>();
    let privileged_denied_claims_present = denied_claim_ids
        .iter()
        .all(|claim| privileged_ids.contains(claim.as_str()));
    assert!(privileged_denied_claims_present);

    QualityFixture {
        fixture,
        scenario,
        provision_subject,
        provision_ingest_report,
        denied_claim_ids,
        privileged_denied_claims_present,
    }
}

pub(super) async fn verify_quality_preflight(
    reads: &ChatReadResources,
    setup: &QualityFixture,
) -> Value {
    reads.begin_turn();
    let cancel = || Arc::new(AtomicBool::new(false));
    let query = |about: &str, direction: &str, predicate: &str| {
        ChatQueryRequest { query: json!({
        "about":[{"from":[about],"match":"exact"}],
        "walk":{"direction":direction,"predicates":[["meta:relation","=",predicate]]},
        "bounds":{"max_depth":1,"seed_limit":8,"fanout_limit":32,"max_claims":32,"path_limit":32}
    }).to_string() }
    };
    let lender = setup.scenario["entities"]["lender"].as_str().unwrap();
    let lender_predicate = setup.scenario["predicates"]["lender"].as_str().unwrap();
    let ChatQueryOutcome::Complete(role) = reads
        .graph_query(query(lender, "incoming", lender_predicate), cancel())
        .await
        .unwrap()
    else {
        panic!("role preflight incomplete")
    };
    assert_eq!(
        role.claims.len(),
        1,
        "Semantic claim denial did not exclude hidden lender edge"
    );
    assert_eq!(
        role.claims[0].subject,
        setup.scenario["entities"]["agreement"]
    );
    let hidden = setup.scenario["entities"]["inaccessible_agreement"]
        .as_str()
        .unwrap();
    assert!(role.nodes.iter().all(|node| node.iri != hidden));

    let ChatQueryOutcome::Complete(agreement) = reads.graph_query(ChatQueryRequest { query: json!({
        "about":[{"from":[setup.provision_subject],"match":"exact"}],
        "bounds":{"max_depth":1,"seed_limit":1,"fanout_limit":32,"max_claims":32,"path_limit":32}
    }).to_string() }, cancel()).await.unwrap() else { panic!("agreement preflight incomplete") };
    let provision = agreement
        .claims
        .iter()
        .find(|claim| claim.predicate == PROVISION)
        .expect("source-backed untyped provision");
    let source = agreement
        .source_references
        .iter()
        .find(|source| source.claim_citation == provision.citation && source.resolvable)
        .expect("resolvable provision source");
    let citation = source.citation.clone().expect("provision source citation");
    let ChatSourceOutcome::Complete(exact) = reads
        .source(
            ChatSourceRequest {
                reference: citation,
                max_bytes: None,
            },
            cancel(),
        )
        .await
        .unwrap()
    else {
        panic!("provision source preflight incomplete")
    };
    assert!(exact.content.contains(QUALITY_QUOTE));

    let ChatQueryOutcome::Complete(ambiguous) = reads.graph_query(ChatQueryRequest { query: json!({
        "about":[{"from":["Atlas Facility"],"match":"approximate"}],
        "walk":{"direction":"outgoing","predicates":[["meta:relation","=",LABEL]]},
        "bounds":{"max_depth":1,"seed_limit":8,"fanout_limit":8,"max_claims":16,"path_limit":16}
    }).to_string() }, cancel()).await.unwrap() else { panic!("ambiguity preflight incomplete") };
    let atlas = ambiguous
        .nodes
        .iter()
        .filter(|node| node.display_label == "Atlas Facility")
        .map(|node| node.iri.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        atlas,
        BTreeSet::from([
            setup.scenario["entities"]["agreement"].as_str().unwrap(),
            setup.scenario["entities"]["ambiguous_agreement"]
                .as_str()
                .unwrap(),
        ])
    );
    assert!(
        ambiguous.nodes.iter().all(|node| node.iri != hidden),
        "denied label support leaked into landing"
    );

    let unsupported = reads
        .dispatch_tool(
            "ctxql_graph_query",
            br#"{"query":"{\"aggregate\":\"all agreements in the world\"}"}"#,
            cancel(),
        )
        .await
        .unwrap();
    assert_eq!(unsupported["status"], "invalid");
    assert!(unsupported.get("result_id").is_none());
    json!({
        "status":"passed_before_transport_start",
        "visible_lender_claim":role.claims[0].claim_id,
        "denied_claim_ids":setup.denied_claim_ids,
        "privileged_setup_contains_denied_claims":setup.privileged_denied_claims_present,
        "hidden_subject_excluded":true,
        "protected_hidden_label_excluded":true,
        "provision_claim":provision.claim_id,
        "provision_source_contains_exact_condition":true,
        "ambiguous_visible_identities":atlas,
        "unsupported_global_status":"invalid"
    })
}
