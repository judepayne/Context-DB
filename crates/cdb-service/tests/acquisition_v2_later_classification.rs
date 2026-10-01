use cdb_core::{classification::UNCLASSIFIED_ENTITY, CanonicalValue, Limits};
use cdb_provider_pi::cancel::CancellationToken;
use cdb_service::{
    acquisition_v2_fixture::AcquisitionV2Fixture,
    ingest::{ingest, IngestMode, IngestWait, OntologyMode},
    source_target::SourceTarget,
};
use std::{fs, path::Path};

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const CREDIT_AGREEMENT: &str = "urn:ctxql:a2:CreditAgreement";
const BORROWER: &str = "urn:ctxql:a2:Borrower";

#[test]
fn later_passage_classification_does_not_remint_earlier_claims() {
    let evidence = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "later_passage_classification_child",
            "--test-threads=1",
        ])
        .env("RUST_MIN_STACK", "33554432")
        .env("OPENROUTER_API_KEY", "ctxql-hermetic-fake-provider-key")
        .env("CDB_A2_EVIDENCE_DIR", evidence.path())
        .status()
        .unwrap();
    assert!(status.success(), "serial later-classification child failed");
}

#[tokio::test]
#[ignore = "run only through the serial environment wrapper"]
async fn later_passage_classification_child() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    install_classification_fake(fixture.root());
    let document = fixture
        .write_document(
            "later-classification.txt",
            b"Opening context says Orion has Acme as borrower.\nOrion is also a borrower in the later classification passage.\n",
        )
        .unwrap();
    let mut config = fixture.config().unwrap();
    let acquisition = config.acquisition.as_mut().unwrap();
    acquisition.window.mode = "always".into();
    acquisition.window.target_bytes = 70;
    acquisition.window.max_bytes = 100;
    acquisition.window.overlap_bytes = 40;
    let capture_path = fixture.root().join("later-classification-capture.json");

    let admitted = ingest(
        config,
        SourceTarget::LocalFile(document.clone()),
        IngestMode::Admit(IngestWait::Admitted),
        OntologyMode::Hard,
        2 * 1024 * 1024,
        None,
        None,
        Some(capture_path.display().to_string()),
        CancellationToken::default(),
    )
    .await
    .unwrap();
    let admitted = serde_json::to_value(admitted).unwrap();
    assert_eq!(admitted["documents"][0]["window_count"], 2);
    assert_eq!(fixture.pi_invocations().unwrap(), 2);
    let claims = admitted["documents"][0]["admitted_claims"]
        .as_array()
        .unwrap();
    let earlier = claims
        .iter()
        .find(|claim| {
            claim["ext"]["ctxql.acquisition.v2/component_ref"] == "relation:host/relation/0"
        })
        .expect("first-passage relation");
    let entity = earlier["subject_id"].as_str().unwrap();
    let earlier_id = earlier["claim_id"].as_str().unwrap().to_owned();
    let earlier_bytes = canonical(earlier);
    let classification = &earlier["ext"]["ctxql.acquisition.classification/v2"];
    assert_eq!(earlier["subject_type"], CREDIT_AGREEMENT);
    assert_eq!(classification["subject"]["status"], "classified");
    assert_eq!(
        classification["subject"]["classes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["iri"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![CREDIT_AGREEMENT],
        "the later Borrower class leaked into the frozen earlier context"
    );

    let explicit_types = claims
        .iter()
        .filter(|claim| claim["relation"] == RDF_TYPE && claim["subject_id"] == entity)
        .map(|claim| claim["object_id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        explicit_types,
        [BORROWER, CREDIT_AGREEMENT].into_iter().collect(),
        "only independently acquired classes may become native types"
    );
    assert!(claims.iter().all(|claim| {
        claim["object_id"].as_str() != Some(UNCLASSIFIED_ENTITY)
            || claim["relation"].as_str() != Some(RDF_TYPE)
    }));

    std::env::remove_var("OPENROUTER_API_KEY");
    let mut replay_config = fixture.config().unwrap();
    let acquisition = replay_config.acquisition.as_mut().unwrap();
    acquisition.window.mode = "always".into();
    acquisition.window.target_bytes = 70;
    acquisition.window.max_bytes = 100;
    acquisition.window.overlap_bytes = 40;
    let replayed = ingest(
        replay_config,
        SourceTarget::LocalFile(document),
        IngestMode::Admit(IngestWait::Admitted),
        OntologyMode::Hard,
        2 * 1024 * 1024,
        None,
        Some(capture_path.display().to_string()),
        None,
        CancellationToken::default(),
    )
    .await
    .unwrap();
    let replayed = serde_json::to_value(replayed).unwrap();
    assert_eq!(
        fixture.pi_invocations().unwrap(),
        2,
        "capture replay called Pi"
    );
    let replayed_earlier = replayed["documents"][0]["admitted_claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|claim| claim["claim_id"] == earlier_id)
        .expect("replay preserved the earlier claim ID");
    assert_eq!(canonical(replayed_earlier), earlier_bytes);
    assert_eq!(
        replayed_earlier["ext"]["ctxql.acquisition.classification/v2"], *classification,
        "replay changed frozen classification metadata"
    );
}

fn canonical(value: &serde_json::Value) -> Vec<u8> {
    CanonicalValue::parse(&serde_json::to_vec(value).unwrap(), Limits::default())
        .unwrap()
        .canonical_bytes(Limits::default())
        .unwrap()
}

fn install_classification_fake(root: &Path) {
    let script = r#"#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(__file__).resolve().parent
for line in sys.stdin:
    rpc = json.loads(line)
    ident = rpc.get("id", "")
    method = rpc.get("method", rpc.get("type", ""))
    if method == "new_session":
        print(json.dumps({"type":"response","id":ident,"success":True,"data":{}}), flush=True)
    elif method == "get_session_stats":
        print(json.dumps({"type":"response","id":ident,"success":True,"data":{"input_tokens":1,"output_tokens":1,"cost_microusd":0}}), flush=True)
    elif method == "prompt":
        if not os.environ.get("OPENROUTER_API_KEY"):
            sys.exit(17)
        prompt = json.loads(rpc["message"])
        window = next(item for item in prompt["ranges"] if item["kind"] == "window")
        handles = prompt["document_entity_handles"]["entries"]
        if not handles:
            text = f"ENTITY:\nId: orion\nName: Orion\nKnown entity: none\nEVIDENCE:\nRange: {window['range']}\nOccurrence: 0\nQuote: Orion\n---\nENTITY:\nId: acme\nName: Acme\nKnown entity: none\nEVIDENCE:\nRange: {window['range']}\nOccurrence: 0\nQuote: Acme\n---\nCLAIM:\nKind: classification\nSubject: local orion\nTerm: urn:ctxql:a2:CreditAgreement\nTerm note:\nTerm selected: 0\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\nEVIDENCE:\nRange: {window['range']}\nOccurrence: 0\nQuote: Opening context says Orion\n---\nCLAIM:\nKind: relation\nSubject: local orion\nPredicate: urn:ctxql:a2:hasBorrower\nPredicate note:\nPredicate selected: 0\nObject: local acme\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\nEVIDENCE:\nRange: {window['range']}\nOccurrence: 0\nQuote: Orion has Acme as borrower\n---"
        else:
            text = f"ENTITY:\nId: orion-later\nName: Orion\nKnown entity: none\nEVIDENCE:\nRange: {window['range']}\nOccurrence: 0\nQuote: Orion\n---\nCLAIM:\nKind: classification\nSubject: local orion-later\nTerm: urn:ctxql:a2:Borrower\nTerm note:\nTerm selected: 0\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\nEVIDENCE:\nRange: {window['range']}\nOccurrence: 0\nQuote: Orion is also a borrower in the later classification passage\n---"
        count = root / "pi-invocations"
        count.write_text(str(int(count.read_text().strip()) + 1) + "\n")
        print(json.dumps({"type":"tool_execution_start","toolCallId":"skill-1","toolName":"ctxql_skill","args":{"name":"read-loan-agreement-v2"}}), flush=True)
        print(json.dumps({"type":"tool_execution_end","toolCallId":"skill-1","toolName":"ctxql_skill","isError":False}), flush=True)
        print(json.dumps({"type":"response","id":ident,"success":True,"data":{}}), flush=True)
        print(json.dumps({"type":"agent_end","model":"deepseek/deepseek-v4.1-flash","messages":[{"role":"assistant","text":text}]}), flush=True)
"#;
    let path = root.join("fake-pi.py");
    fs::write(&path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
