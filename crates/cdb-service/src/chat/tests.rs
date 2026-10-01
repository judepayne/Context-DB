use super::*;
use crate::{
    acquisition::{AcquisitionService, AdmissionContext, WaitPoint},
    acquisition_v2_fixture::AcquisitionV2Fixture,
    config::{ArtifactReference, ChatConfig, ChatLimits},
    ingest::{ingest, IngestMode, IngestWait, OntologyMode},
    source_target::SourceTarget,
    sources::acquisition_selector_records,
    Service,
};
use cdb_backend_fluree::official_bootstrap::ACQUISITION_V2_FIXTURE_PRINCIPAL;
use cdb_core::{
    admission::ExportRecord,
    artifact::{ArtifactRef, PublishedArtifact},
    contracts::{GraphBackend, SemanticProjectionSource},
    id::{
        AttemptId, BundleId, ContentHash, ExtractionRunId, IdempotencyKey, Iri, JobId, PrincipalId,
        VersionId,
    },
    policy::PolicySet,
    semantic_admission::{stable_acquisition_v2_claim_id, ValidatedSemanticBundle},
    CanonicalValue as V, ErrorKind, Limits, Timestamp,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    sync::{atomic::AtomicBool, Arc},
};

const LABEL: &str = "http://www.w3.org/2000/01/rdf-schema#label";
const VALUE: &str = "urn:ctxql:chat-test:status";

async fn publish_artifact(
    service: &Arc<Service>,
    token: &str,
    iri: &str,
    content: &[u8],
) -> ArtifactRef {
    let reference = ArtifactRef::new(
        Iri::new(iri).unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(content),
    );
    let published =
        PublishedArtifact::new(reference.clone(), content.to_vec(), Limits::default()).unwrap();
    let artifact: serde_json::Value = serde_json::from_slice(
        &published
            .reference()
            .projection()
            .canonical_bytes(Limits::default())
            .unwrap(),
    )
    .unwrap();
    service
        .dispatch(
            token,
            &serde_json::to_vec(&serde_json::json!({
                "schema":"ctxql-service/v1",
                "op":"publish",
                "artifact":artifact,
                "content":String::from_utf8(published.content().to_vec()).unwrap()
            }))
            .unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    reference
}

fn chat_config(
    fixture: &AcquisitionV2Fixture,
    query_config: &ArtifactRef,
    profile: Option<(&str, &ArtifactRef)>,
) -> crate::config::InstanceConfig {
    let mut config = fixture.config().unwrap();
    let acquisition = config.acquisition.take().unwrap();
    config.schema = "ctxql-instance/v3".into();
    let reference = |artifact: &ArtifactRef| ArtifactReference {
        iri: artifact.iri().as_str().into(),
        version: artifact.version().as_str().into(),
        hash: artifact.hash().as_str().into(),
    };
    config.chat = Some(ChatConfig {
        unsafe_direct_projection: false,
        pi_command: acquisition.pi_command,
        pi_bundle: acquisition.pi_bundle,
        pi_session_log_dir: None,
        chat_model: cdb_provider_pi::MODEL.into(),
        thinking: cdb_provider_pi::THINKING.into(),
        query_config: reference(query_config),
        profile_selector: profile.map(|(selector, _)| selector.to_owned()),
        profile: profile.map(|(_, artifact)| reference(artifact)),
        ontology: None,
        limits: ChatLimits::default(),
    });
    config.validate_runtime().unwrap();
    config
}

fn semantic_literal_claim(
    component: &str,
    subject: &str,
    predicate: &str,
    lexical: &str,
) -> cdb_core::claim::CandidateClaim {
    let mut value = V::parse(
        br#"{"claim_id":"urn:ctxql:claim:v2:placeholder","claim_type":"urn:type:claim","confidence":1,"ext":{"ctxql.acquisition.v2/claim_identity":"stable-component/v1","ctxql.acquisition.v2/component_ref":"placeholder"},"grounding_level":"source_lineage_available","lineage":{"schema":"ctxql.lineage.v1","sources":[{"source_id":"urn:source:chat-projection","kind":"document","uri":"urn:evidence:chat-projection"}]},"object_id":{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#string","value":"placeholder","language":null},"object_type":"http://www.w3.org/2001/XMLSchema#string","relation":"urn:predicate:placeholder","relation_type":"urn:type:relation","subject_id":"urn:subject:placeholder","subject_type":"urn:type:entity"}"#,
        Limits::default(),
    )
    .unwrap();
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
    let provisional = cdb_core::claim::CandidateClaim::from_value(&value).unwrap();
    let id = stable_acquisition_v2_claim_id(&provisional, Limits::default()).unwrap();
    let V::Object(fields) = &mut value else {
        unreachable!()
    };
    fields.insert("claim_id".into(), V::string(id.as_str()));
    cdb_core::claim::CandidateClaim::from_value(&value).unwrap()
}

async fn admit_claims(
    fixture: &AcquisitionV2Fixture,
    claims: Vec<cdb_core::claim::CandidateClaim>,
    suffix: &str,
) {
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

async fn admit_projection_claims(fixture: &AcquisitionV2Fixture) {
    admit_claims(
        fixture,
        vec![
            semantic_literal_claim("chat#a-label", "urn:chat:entity:a", LABEL, "Shared Name"),
            semantic_literal_claim("chat#b-label", "urn:chat:entity:b", LABEL, "Shared Name"),
            semantic_literal_claim("chat#a-status-1", "urn:chat:entity:a", VALUE, "active"),
            semantic_literal_claim("chat#a-status-2", "urn:chat:entity:a", VALUE, "inactive"),
            semantic_literal_claim("chat#b-status", "urn:chat:entity:b", VALUE, "pending"),
        ],
        "chat-projection",
    )
    .await;
}

fn inventory(root: &Path) -> BTreeMap<String, (u64, Option<String>)> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<String, (u64, Option<String>)>) {
        let mut entries = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                out.insert(relative, (0, None));
                visit(root, &path, out);
            } else {
                let bytes = fs::read(&path).unwrap();
                out.insert(
                    relative,
                    (
                        bytes.len() as u64,
                        Some(ContentHash::of_bytes(&bytes).as_str().into()),
                    ),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

async fn set_subject_denial(resources: &ChatReadResources, subject: &str, tag: &str) {
    let mut state = resources
        .control
        .as_ref()
        .unwrap()
        .policy_state()
        .await
        .unwrap();
    state.policy = PolicySet::parse(
        format!(
            r#"{{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{{"@id":"https://ctxql.example/test/chat-allow","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceReader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true}},{{"@id":"https://ctxql.example/test/chat-deny","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceReader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#onSubject":{},"https://ns.flur.ee/db#allow":false}}]}}"#,
            serde_json::to_string(subject).unwrap()
        )
        .as_bytes(),
        Limits::default(),
    )
    .unwrap();
    let head = GraphBackend::head(resources.control.as_ref().unwrap().as_ref())
        .await
        .unwrap();
    resources
        .control
        .as_ref()
        .unwrap()
        .set_policy_state(
            &IdempotencyKey::new(format!("chat-{tag}-{}", head.pin().revision().as_str())).unwrap(),
            &state,
        )
        .await
        .unwrap();
}

async fn restore_policy(
    resources: &ChatReadResources,
    state: &cdb_backend_fluree::policy::PolicyState,
    tag: &str,
) {
    let head = GraphBackend::head(resources.control.as_ref().unwrap().as_ref())
        .await
        .unwrap();
    resources
        .control
        .as_ref()
        .unwrap()
        .set_policy_state(
            &IdempotencyKey::new(format!("chat-{tag}-{}", head.pin().revision().as_str())).unwrap(),
            state,
        )
        .await
        .unwrap();
}

fn projection_query() -> ChatQueryRequest {
    ChatQueryRequest {
        query: serde_json::json!({
            "profile":"tiny/default",
            "about":[{"from":["Shared Name"],"match":"approximate"}],
            "walk":{"direction":"outgoing","predicates":[["meta:relation","=",VALUE]]},
            "bounds":{"max_depth":1,"seed_limit":8,"fanout_limit":8,"max_claims":16,"path_limit":16}
        })
        .to_string(),
    }
}

#[tokio::test]
#[ignore = "run exactly through the serial native-test wrapper"]
async fn malformed_requests_exhaust_lifetime_budgets_before_response_work() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let token = fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    let service = Service::open(fixture.config().unwrap()).await.unwrap();
    let reference = publish_artifact(
        &service,
        &token,
        "https://ctxql.example/test/chat-budget-config",
        include_bytes!("../../../../fixtures/conformance/graph-workspace/config.json"),
    )
    .await;
    service.shutdown().await.unwrap();
    drop(service);
    admit_projection_claims(&fixture).await;
    let mut config = chat_config(&fixture, &reference, None);
    let limits = &mut config.chat.as_mut().unwrap().limits;
    limits.max_tool_calls = 4;
    limits.max_queries = 2;
    limits.max_queries_per_turn = 2;
    let reads = ChatReadResources::open(config, token).await.unwrap();
    let cancel = || Arc::new(AtomicBool::new(false));
    reads
        .dispatch_tool("ctxql_source", br#"{"reference":7}"#, cancel())
        .await
        .unwrap();
    reads
        .dispatch_tool("ctxql_graph_query", br#"{"query":7}"#, cancel())
        .await
        .unwrap();
    reads.begin_turn();
    reads
        .dispatch_tool("ctxql_graph_query", br#"{"unknown":"field"}"#, cancel())
        .await
        .unwrap();
    let error = reads
        .dispatch_tool("ctxql_graph_query", b"{}", cancel())
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Limit);
    // A valid tool consumes exactly one slot, not a dispatcher plus adapter slot.
    reads
        .dispatch_tool("ctxql_capabilities", b"{}", cancel())
        .await
        .unwrap();
    for _ in 0..2 {
        reads.begin_turn();
        reads.clear_epoch();
        for (tool, payload) in [
            ("ctxql_source", br#"{"reference":7}"#.as_slice()),
            ("ctxql_capabilities", br#"{"extra":true}"#.as_slice()),
            ("ctxql_graph_query", b"{}".as_slice()),
            ("ctxql_source", b"not json".as_slice()),
            (
                "ctxql_source",
                br#"{"reference":"S1","reference":"S2"}"#.as_slice(),
            ),
            ("unknown_tool", b"{}".as_slice()),
        ] {
            assert_eq!(
                reads
                    .dispatch_tool(tool, payload, cancel())
                    .await
                    .unwrap_err()
                    .kind,
                ErrorKind::Limit
            );
        }
        assert_eq!(
            reads.capabilities(cancel()).await.unwrap_err().kind,
            ErrorKind::Limit
        );
    }
}

#[tokio::test]
#[ignore = "run exactly through the serial native-test wrapper"]
async fn projection_keeps_labels_untyped_conflicts_and_concurrent_reads_immutable() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let token = fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    let service = Service::open(fixture.config().unwrap()).await.unwrap();
    let query_config = publish_artifact(
        &service,
        &token,
        "https://ctxql.example/test/chat-projection-config",
        include_bytes!("../../../../fixtures/conformance/graph-workspace/config.json"),
    )
    .await;
    let profile = publish_artifact(
        &service,
        &token,
        "https://ctxql.example/test/chat-projection-profile",
        br#"{"name":"tiny/default","bounds":{"max_depth":1},"return":{"claims":true,"paths":true,"evidence":false,"explain":false}}"#,
    )
    .await;
    service.shutdown().await.unwrap();
    drop(service);
    admit_projection_claims(&fixture).await;

    let config = chat_config(&fixture, &query_config, Some(("tiny/default", &profile)));
    let source_before = inventory(&config.source_root);
    let reads = ChatReadResources::open(config, token).await.unwrap();
    reads.begin_turn();
    let semantic_before = SemanticProjectionSource::head(reads.semantic.as_ref())
        .await
        .unwrap();
    let control_before = GraphBackend::head(reads.control.as_ref().unwrap().as_ref())
        .await
        .unwrap();

    let first_reads = reads.clone();
    let second_reads = reads.clone();
    let first = tokio::spawn(async move {
        first_reads
            .graph_query(projection_query(), Arc::new(AtomicBool::new(false)))
            .await
    });
    let second = tokio::spawn(async move {
        second_reads
            .graph_query(projection_query(), Arc::new(AtomicBool::new(false)))
            .await
    });
    let outcomes = vec![
        first.await.unwrap().unwrap(),
        second.await.unwrap().unwrap(),
    ];
    let mut result_ids = BTreeSet::new();
    for outcome in outcomes {
        let ChatQueryOutcome::Complete(result) = outcome else {
            panic!("concurrent read returned a diagnostic")
        };
        result_ids.insert(result.result_id.clone());
        assert_eq!(result.claims.len(), 3);
        assert!(result.claims.iter().all(|claim| claim.predicate == VALUE));
        assert!(result.claims.iter().all(|claim| claim.predicate != LABEL));
        let named = result
            .nodes
            .iter()
            .filter(|node| matches!(node.iri.as_str(), "urn:chat:entity:a" | "urn:chat:entity:b"))
            .collect::<Vec<_>>();
        assert_eq!(named.len(), 2, "equal labels collapsed distinct identities");
        assert!(named.iter().all(|node| {
            node.display_label == "Shared Name"
                && node.labels.iter().any(|label| label.value == "Shared Name")
        }));
        let conflicts = result
            .claims
            .iter()
            .filter(|claim| claim.subject == "urn:chat:entity:a")
            .collect::<Vec<_>>();
        assert_eq!(conflicts.len(), 2);
        assert_ne!(conflicts[0].claim_id, conflicts[1].claim_id);
        let values = conflicts
            .iter()
            .filter_map(|claim| match &claim.object {
                ChatObject::Literal { value, .. } => value.as_str(),
                ChatObject::Entity { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(values, BTreeSet::from(["active", "inactive"]));
    }
    assert_eq!(
        result_ids.len(),
        2,
        "concurrent calls reused a result identity"
    );
    assert_eq!(
        SemanticProjectionSource::head(reads.semantic.as_ref())
            .await
            .unwrap(),
        semantic_before
    );
    assert_eq!(
        GraphBackend::head(reads.control.as_ref().unwrap().as_ref())
            .await
            .unwrap(),
        control_before
    );
    assert_eq!(inventory(&reads.config.source_root), source_before);

    let original_policy = reads
        .control
        .as_ref()
        .unwrap()
        .policy_state()
        .await
        .unwrap();
    set_subject_denial(&reads, query_config.iri().as_str(), "deny-config").await;
    let denied = reads
        .graph_query(projection_query(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap_err();
    assert_eq!(denied.kind, ErrorKind::Denied);
    restore_policy(&reads, &original_policy, "restore-config").await;
    set_subject_denial(&reads, profile.iri().as_str(), "deny-profile").await;
    let denied = reads
        .graph_query(projection_query(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap_err();
    assert_eq!(denied.kind, ErrorKind::Denied);
}

#[tokio::test]
#[ignore = "run exactly through the serial native-test wrapper"]
async fn missing_and_stale_projection_never_fall_back_or_repair_original() {
    fn copy_new_tree(from: &Path, to: &Path) {
        assert!(!to.exists());
        fs::create_dir(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            let kind = entry.file_type().unwrap();
            assert!(!kind.is_symlink());
            if kind.is_dir() {
                copy_new_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }
    for missing in [true, false] {
        let fixture = AcquisitionV2Fixture::create().await.unwrap();
        let token = fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
        let service = Service::open(fixture.config().unwrap()).await.unwrap();
        let query_config = publish_artifact(
            &service,
            &token,
            "https://ctxql.example/test/chat-stale-config",
            include_bytes!("../../../../fixtures/conformance/graph-workspace/config.json"),
        )
        .await;
        service.shutdown().await.unwrap();
        drop(service);
        let projection = fixture.config().unwrap().projection;
        let old = fixture.root().join("older-projection");
        copy_new_tree(&projection, &old);
        admit_projection_claims(&fixture).await;
        let config = chat_config(&fixture, &query_config, None);
        let sources_before = inventory(&config.source_root);
        let reads = ChatReadResources::open(config, token).await.unwrap();
        reads.begin_turn();
        let query = ChatQueryRequest {
            query: serde_json::json!({
                "about":[{"from":["urn:chat:entity:a"],"match":"exact"}],
                "bounds":{"max_depth":1,"seed_limit":1,"fanout_limit":8,"max_claims":16,"path_limit":16}
            }).to_string(),
        };
        assert!(matches!(
            reads
                .graph_query(query.clone(), Arc::new(AtomicBool::new(false)))
                .await
                .unwrap(),
            ChatQueryOutcome::Complete(_)
        ));
        let semantic_before = SemanticProjectionSource::head(reads.semantic.as_ref())
            .await
            .unwrap();
        let control_before = GraphBackend::head(reads.control.as_ref().unwrap().as_ref())
            .await
            .unwrap();
        // Only these disposable test-owned paths are moved. Keep the valid
        // generation rather than deleting it; never invoke a repair service.
        fs::rename(
            &projection,
            fixture.root().join("retained-current-projection"),
        )
        .unwrap();
        if !missing {
            copy_new_tree(&old, &projection);
        }
        let before = if missing {
            BTreeMap::new()
        } else {
            inventory(&projection)
        };
        let outcome = reads
            .graph_query(query, Arc::new(AtomicBool::new(false)))
            .await;
        assert!(
            !matches!(outcome, Ok(ChatQueryOutcome::Complete(_))),
            "missing/stale projection produced a usable graph"
        );
        if missing {
            assert!(!projection.exists(), "read repaired the missing original");
        } else {
            assert_eq!(
                inventory(&projection),
                before,
                "read repaired the stale original"
            );
        }
        assert_eq!(
            SemanticProjectionSource::head(reads.semantic.as_ref())
                .await
                .unwrap(),
            semantic_before
        );
        assert_eq!(
            GraphBackend::head(reads.control.as_ref().unwrap().as_ref())
                .await
                .unwrap(),
            control_before
        );
        assert_eq!(inventory(&reads.config.source_root), sources_before);
    }
}

#[tokio::test]
#[ignore = "run exactly through the serial native-test wrapper"]
async fn checked_quality_scenarios_use_authorized_host_outcomes_not_scripted_answers() {
    let setup = crate::chat::quality_fixture::setup_quality_fixture().await;
    let fixture = &setup.fixture;
    let scenario = &setup.scenario;
    assert_eq!(scenario["schema"], "ctxql.chat-quality-scenarios/v1");
    let scenario_ids = scenario["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        scenario_ids,
        BTreeSet::from([
            "ambiguous-name",
            "global-unsupported",
            "party-role",
            "untyped-provision",
        ])
    );
    let token = fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    let service = Service::open(fixture.config().unwrap()).await.unwrap();
    let query_config = publish_artifact(
        &service,
        &token,
        "https://ctxql.example/test/chat-quality-config",
        include_bytes!("../../../../fixtures/conformance/graph-workspace/config.json"),
    )
    .await;
    service.shutdown().await.unwrap();
    drop(service);

    let config = chat_config(fixture, &query_config, None);
    assert!(config.acquisition.is_none());
    let source_before = inventory(&config.source_root);
    let reads = ChatReadResources::open(config, token).await.unwrap();
    let semantic_before = SemanticProjectionSource::head(reads.semantic.as_ref())
        .await
        .unwrap();
    let control_before = GraphBackend::head(reads.control.as_ref().unwrap().as_ref())
        .await
        .unwrap();
    let preflight = crate::chat::quality_fixture::verify_quality_preflight(&reads, &setup).await;
    assert_eq!(preflight["status"], "passed_before_transport_start");
    reads.begin_turn();
    let cancel = || Arc::new(AtomicBool::new(false));
    let query = |about: &str, direction: &str, predicate: &str| {
        ChatQueryRequest {
        query: serde_json::json!({
            "about":[{"from":[about],"match":"exact"}],
            "walk":{"direction":direction,"predicates":[["meta:relation","=",predicate]]},
            "bounds":{"max_depth":1,"seed_limit":8,"fanout_limit":16,"max_claims":32,"path_limit":16}
        })
        .to_string(),
    }
    };

    // The role-specific incoming query returns the lender edge and does not
    // substitute the arranger role.
    let ChatQueryOutcome::Complete(lenders) = reads
        .graph_query(
            query(
                scenario["entities"]["lender"].as_str().unwrap(),
                "incoming",
                scenario["predicates"]["lender"].as_str().unwrap(),
            ),
            cancel(),
        )
        .await
        .unwrap()
    else {
        panic!("expected lender result")
    };
    assert_eq!(lenders.claims.len(), 1);
    assert_eq!(
        lenders.claims[0].subject,
        scenario["entities"]["agreement"].as_str().unwrap()
    );
    assert_eq!(
        lenders.claims[0].predicate,
        scenario["predicates"]["lender"].as_str().unwrap()
    );

    // Exact-ID traversal retains explicit typing, the separate arranger edge,
    // an untyped custom provision, and both conflicting status claims.
    let agreement = scenario["entities"]["agreement"].as_str().unwrap();
    let ChatQueryOutcome::Complete(agreement_result) = reads
        .graph_query(
            ChatQueryRequest {
                query: serde_json::json!({
                    "about":[{"from":[agreement],"match":"exact"}],
                    "bounds":{"max_depth":1,"seed_limit":1,"fanout_limit":32,"max_claims":32,"path_limit":32}
                })
                .to_string(),
            },
            cancel(),
        )
        .await
        .unwrap()
    else {
        panic!("expected agreement result")
    };
    let predicates = agreement_result
        .claims
        .iter()
        .map(|claim| claim.predicate.as_str())
        .collect::<Vec<_>>();
    for predicate in ["type", "lender", "arranger", "provision"] {
        assert!(predicates.contains(&scenario["predicates"][predicate].as_str().unwrap()));
    }
    assert_eq!(
        predicates
            .iter()
            .filter(|predicate| **predicate == scenario["predicates"]["status"].as_str().unwrap())
            .count(),
        2,
        "conflicting claims were folded"
    );

    // Approximate landing reports both authorized identities with the same
    // visible name; the host does not pick one and manufacture certainty.
    let ChatQueryOutcome::Complete(ambiguous) = reads
        .graph_query(
            ChatQueryRequest {
                query: serde_json::json!({
                    "about":[{"from":["Atlas Facility"],"match":"approximate"}],
                    "walk":{"direction":"outgoing","predicates":[["meta:relation","=",LABEL]]},
                    "bounds":{"max_depth":1,"seed_limit":8,"fanout_limit":8,"max_claims":16,"path_limit":16}
                })
                .to_string(),
            },
            cancel(),
        )
        .await
        .unwrap()
    else {
        panic!("expected ambiguous-name result")
    };
    let atlas_ids = ambiguous
        .nodes
        .iter()
        .filter(|node| node.display_label == "Atlas Facility")
        .map(|node| node.iri.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        atlas_ids,
        BTreeSet::from([
            scenario["entities"]["agreement"].as_str().unwrap(),
            scenario["entities"]["ambiguous_agreement"]
                .as_str()
                .unwrap(),
        ])
    );

    // A global aggregation is outside this restricted CTXQL profile. The actual
    // host diagnostic has no fabricated result handle or prose answer.
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

    assert_eq!(
        SemanticProjectionSource::head(reads.semantic.as_ref())
            .await
            .unwrap(),
        semantic_before,
        "quality reads changed Semantic"
    );
    assert_eq!(
        GraphBackend::head(reads.control.as_ref().unwrap().as_ref())
            .await
            .unwrap(),
        control_before,
        "quality reads changed Control"
    );
    assert_eq!(inventory(&reads.config.source_root), source_before);
}

#[tokio::test]
#[ignore = "run exactly through the serial native-test wrapper"]
async fn exact_span_overflow_and_selector_revocation_do_not_remove_query_access() {
    std::env::set_var("OPENROUTER_API_KEY", "ctxql-hermetic-fake-provider-key");
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let document = fixture
        .write_document(
            "chat-selector.txt",
            b"Orion is a written agreement under which Acme Ltd borrows GBP 1000.\nOrion was executed on 2022-12-06.\nOrion agreement date: 2022-12-06.\n",
        )
        .unwrap();
    fixture
        .set_pi_response(include_str!(
            "../../../../fixtures/conformance/p6/ontology-guided/a2-proposals-v2.json"
        ))
        .unwrap();
    let report = ingest(
        fixture.config().unwrap(),
        SourceTarget::LocalFile(document),
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
    let report = serde_json::to_value(report).unwrap();
    let subject = report["documents"][0]["admitted_claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|claim| claim["relation"] == "urn:ctxql:a2:executedOn")
        .unwrap()["subject_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    let service = Service::open(fixture.config().unwrap()).await.unwrap();
    let query_config = publish_artifact(
        &service,
        &token,
        "https://ctxql.example/test/chat-selector-config",
        include_bytes!("../../../../fixtures/conformance/graph-workspace/config.json"),
    )
    .await;
    service.shutdown().await.unwrap();
    drop(service);

    let config = chat_config(&fixture, &query_config, None);
    let source_before = inventory(&config.source_root);
    let reads = ChatReadResources::open(config, token).await.unwrap();
    reads.begin_turn();
    let semantic_before = SemanticProjectionSource::head(reads.semantic.as_ref())
        .await
        .unwrap();
    let query = ChatQueryRequest {
        query: serde_json::json!({
            "about":[{"from":[subject],"match":"exact"}],
            "bounds":{"max_depth":1,"seed_limit":1,"fanout_limit":16,"max_claims":32,"path_limit":16}
        })
        .to_string(),
    };
    let ChatQueryOutcome::Complete(result) = reads
        .graph_query(query.clone(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap()
    else {
        panic!("expected complete graph")
    };
    let source = result
        .source_references
        .iter()
        .find(|source| source.resolvable && source.reference["selectors"]["line"].is_object())
        .expect("rich source reference");
    let citation = source.citation.clone().unwrap();
    let overflow = reads
        .source(
            ChatSourceRequest {
                reference: citation.clone(),
                max_bytes: Some(1),
            },
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert!(matches!(
        overflow,
        ChatSourceOutcome::Diagnostic(ChatDiagnostic::SourceTooLarge)
    ));
    let reference = reads
        .state
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .source(&citation)
        .unwrap();
    let selector_id = acquisition_selector_records(&reference, reads.max_source_span_bytes())
        .unwrap()
        .into_iter()
        .filter_map(|record| match record {
            ExportRecord::Resource(record) => Some(record.id().as_str().to_owned()),
            _ => None,
        })
        .next_back()
        .expect("exact rich-selector descriptor");
    set_subject_denial(&reads, &selector_id, "deny-selector").await;
    let revoked_head = GraphBackend::head(reads.control.as_ref().unwrap().as_ref())
        .await
        .unwrap();
    let denied = reads
        .source(
            ChatSourceRequest {
                reference: citation,
                max_bytes: None,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap_err();
    assert_eq!(denied.kind, ErrorKind::Denied);
    assert!(matches!(
        reads
            .graph_query(query, Arc::new(AtomicBool::new(false)))
            .await
            .unwrap(),
        ChatQueryOutcome::Complete(_)
    ));
    assert_eq!(
        GraphBackend::head(reads.control.as_ref().unwrap().as_ref())
            .await
            .unwrap(),
        revoked_head,
        "denied source/query reads changed Control"
    );
    assert_eq!(
        SemanticProjectionSource::head(reads.semantic.as_ref())
            .await
            .unwrap(),
        semantic_before,
        "source/query reads changed Semantic"
    );
    assert_eq!(inventory(&reads.config.source_root), source_before);
    assert!(reads
        .control
        .as_ref()
        .unwrap()
        .policy_state()
        .await
        .unwrap()
        .principals
        .contains_key(&PrincipalId::new(ACQUISITION_V2_FIXTURE_PRINCIPAL).unwrap()));
    std::env::remove_var("OPENROUTER_API_KEY");
}

#[tokio::test]
#[ignore = "run exactly through the serial native-test wrapper"]
async fn unsafe_projection_bypasses_graph_policy_and_refreshes_each_query() {
    let hidden = semantic_literal_claim("unsafe#hidden", "urn:chat:entity:a", VALUE, "hidden");
    let hidden_id = hidden.id().as_str().to_owned();
    let fixture =
        AcquisitionV2Fixture::create_with_semantic_denials(std::slice::from_ref(&hidden_id))
            .await
            .unwrap();
    let token = fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    let service = Service::open(fixture.config().unwrap()).await.unwrap();
    let query_config = publish_artifact(
        &service,
        &token,
        "urn:chat:unsafe-config",
        include_bytes!("../../../../fixtures/conformance/graph-workspace/config.json"),
    )
    .await;
    service.shutdown().await.unwrap();
    drop(service);
    admit_claims(
        &fixture,
        vec![
            semantic_literal_claim("unsafe#label", "urn:chat:entity:a", LABEL, "Shared Name"),
            hidden,
        ],
        "unsafe-first",
    )
    .await;
    let config = chat_config(&fixture, &query_config, None);
    let projection_query = || {
        let mut query: serde_json::Value = serde_json::from_str(&projection_query().query).unwrap();
        query.as_object_mut().unwrap().remove("profile");
        ChatQueryRequest {
            query: query.to_string(),
        }
    };
    let safe = ChatReadResources::open(chat_config(&fixture, &query_config, None), token.clone())
        .await
        .unwrap();
    let ChatQueryOutcome::Complete(result) = safe
        .graph_query(projection_query(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap()
    else {
        panic!("safe query incomplete")
    };
    assert!(result.claims.iter().all(|c| c.claim_id != hidden_id));
    assert_eq!(result.graph_permissions, "enforced");
    drop(safe);
    let mut config = config;
    config.chat.as_mut().unwrap().unsafe_direct_projection = true;
    let reads = ChatReadResources::open(config, token).await.unwrap();
    let caps = reads
        .capabilities(Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(caps.graph_permissions, "bypassed_unsafe_direct_projection");
    assert!(!caps.stored_predicate_fields);
    let ChatQueryOutcome::Complete(first) = reads
        .graph_query(projection_query(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap()
    else {
        panic!("unsafe query incomplete")
    };
    assert_eq!(first.claims.len(), 1);
    assert_eq!(first.claims[0].claim_id, hidden_id);
    assert_eq!(first.graph_permissions, "bypassed_unsafe_direct_projection");
    // No session-long redb ownership or frozen snapshot: ordinary admission can
    // open/update the projection between queries in this same chat session.
    admit_claims(
        &fixture,
        vec![semantic_literal_claim(
            "unsafe#new",
            "urn:chat:entity:a",
            VALUE,
            "new",
        )],
        "unsafe-second",
    )
    .await;
    // Projected admission may publish a complete cached generation before the
    // coordinator promotes it to active. The fresh query must see it already.
    let ChatQueryOutcome::Complete(second) = reads
        .graph_query(projection_query(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap()
    else {
        panic!("second unsafe query incomplete")
    };
    assert_eq!(second.claims.len(), 2);
    assert_ne!(first.snapshot.revision, second.snapshot.revision);
    assert!(reads
        .graph_query(projection_query(), Arc::new(AtomicBool::new(true)))
        .await
        .is_err());
    let mut too_broad: serde_json::Value = serde_json::from_str(&projection_query().query).unwrap();
    too_broad["bounds"]["max_claims"] = serde_json::json!(1);
    assert!(matches!(
        reads
            .graph_query(
                ChatQueryRequest {
                    query: too_broad.to_string()
                },
                Arc::new(AtomicBool::new(false))
            )
            .await
            .unwrap(),
        ChatQueryOutcome::Diagnostic(_)
    ));
}
