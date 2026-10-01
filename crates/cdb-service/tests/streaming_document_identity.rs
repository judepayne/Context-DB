#[path = "support/wal_cleanup.rs"]
mod wal_cleanup;

use cdb_provider_pi::cancel::CancellationToken;
use cdb_service::{
    acquisition_v2_fixture::AcquisitionV2Fixture,
    ingest::{ingest, IngestMode, IngestWait, OntologyMode},
    source_target::SourceTarget,
};
use std::{fs, path::Path};

#[test]
fn streaming_document_handles_survive_reopen_and_extract_only_is_ephemeral() {
    let evidence = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "streaming_document_identity_child",
            "--test-threads=1",
        ])
        .env("RUST_MIN_STACK", "33554432")
        .env("OPENROUTER_API_KEY", "ctxql-hermetic-fake-provider-key")
        .env("CDB_A2_EVIDENCE_DIR", evidence.path())
        .status()
        .unwrap();
    assert!(status.success(), "serial streaming identity child failed");
}

#[tokio::test]
#[ignore = "run only through the serial environment wrapper"]
async fn streaming_document_identity_child() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    install_streaming_fake(fixture.root());
    let document = fixture
        .write_document(
            "streaming.txt",
            b"Orion is the agreement described in this first passage.\n\nOrion borrows from Acme in this second passage.\n",
        )
        .unwrap();
    let mut config = fixture.config().unwrap();
    let acquisition = config.acquisition.as_mut().unwrap();
    acquisition.window.mode = "always".into();
    acquisition.window.target_bytes = 56;
    acquisition.window.max_bytes = 64;
    acquisition.window.overlap_bytes = 0;

    let capture_path = fixture.root().join("multi-passage-capture.json");
    let report = ingest(
        config,
        SourceTarget::LocalFile(document.clone()),
        IngestMode::ExtractOnly,
        OntologyMode::Hard,
        2 * 1024 * 1024,
        None,
        None,
        Some(capture_path.display().to_string()),
        CancellationToken::default(),
    )
    .await
    .unwrap();
    let report = serde_json::to_value(report).unwrap();
    assert_eq!(report["documents"][0]["window_count"], 2);
    assert_eq!(fixture.pi_invocations().unwrap(), 2);
    let prompts: Vec<serde_json::Value> =
        fs::read_to_string(fixture.root().join("pi-prompts.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
    assert_eq!(prompts.len(), 2);
    assert!(prompts[0]["document_entity_handles"]["entries"]
        .as_array()
        .unwrap()
        .is_empty());
    let issued = prompts[1]["document_entity_handles"]["entries"][0]["handle"]
        .as_str()
        .unwrap();
    assert!(issued.starts_with("deh_v1_"));
    assert_ne!(prompts[0]["request_seed"], prompts[1]["request_seed"]);
    assert_ne!(
        prompts[0]["prior_context_checkpoint"],
        prompts[1]["prior_context_checkpoint"]
    );

    let capture_bytes = fs::read(&capture_path).unwrap();
    cdb_service::ingest::verify_capture_manifest_bytes(&capture_bytes).unwrap();
    let capture: serde_json::Value = serde_json::from_slice(&capture_bytes).unwrap();
    assert_eq!(
        capture["schema"],
        "ctxql-provider-multipassage-capture-manifest/v1"
    );
    assert_eq!(capture["passage_count"], 2);
    assert_eq!(capture["leaves"].as_array().unwrap().len(), 2);
    assert_ne!(
        capture["leaves"][0]["request_seed"],
        capture["leaves"][1]["request_seed"]
    );
    assert_eq!(
        capture["leaves"][0]["context_after"],
        capture["leaves"][1]["context_before"]
    );

    assert_capture_rejected(
        mutate_capture(&capture, |value| {
            value["leaves"].as_array_mut().unwrap().pop();
        }),
        "missing passage ordinals [1]",
    );
    assert_capture_rejected(
        mutate_capture(&capture, |value| {
            value["leaves"].as_array_mut().unwrap().swap(0, 1);
        }),
        "passage order mismatch at ordinal 0",
    );
    assert_capture_rejected(
        mutate_capture(&capture, |value| {
            value["leaves"][1]["response"] = serde_json::Value::String("tampered".into());
        }),
        "passage 1 commitment mismatch",
    );

    std::env::remove_var("OPENROUTER_API_KEY");
    let mut replay_config = fixture.config().unwrap();
    let replay_acquisition = replay_config.acquisition.as_mut().unwrap();
    replay_acquisition.window.mode = "always".into();
    replay_acquisition.window.target_bytes = 56;
    replay_acquisition.window.max_bytes = 64;
    replay_acquisition.window.overlap_bytes = 0;
    let replayed = ingest(
        replay_config,
        SourceTarget::LocalFile(document.clone()),
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
    let report = serde_json::to_value(replayed).unwrap();
    assert_eq!(report["documents"][0]["window_count"], 2);
    assert_eq!(
        fixture.pi_invocations().unwrap(),
        2,
        "capture import called provider"
    );
    let claims = report["documents"][0]["admitted_claims"]
        .as_array()
        .unwrap();
    let relation = claims
        .iter()
        .find(|claim| {
            claim["ext"]["ctxql.acquisition.v2/component_ref"] == "relation:host/relation/0"
        })
        .expect("cross-passage relation");
    assert!(relation["subject_id"]
        .as_str()
        .unwrap()
        .starts_with("urn:ctxql:entity:document:v2:"));
    assert_ne!(relation["subject_id"], relation["object_id"]);

    let mut config = fixture.config().unwrap();
    let acquisition = config.acquisition.as_mut().unwrap();
    acquisition.window.mode = "always".into();
    acquisition.window.target_bytes = 56;
    acquisition.window.max_bytes = 64;
    acquisition.window.overlap_bytes = 0;
    let reopened = ingest(
        config,
        SourceTarget::LocalFile(document),
        IngestMode::Admit(IngestWait::Admitted),
        OntologyMode::Hard,
        2 * 1024 * 1024,
        None,
        None,
        None,
        CancellationToken::default(),
    )
    .await
    .unwrap();
    let reopened = serde_json::to_value(reopened).unwrap();
    assert_eq!(
        fixture.pi_invocations().unwrap(),
        2,
        "resume called provider"
    );
    assert_eq!(
        reopened["documents"][0]["admitted_claims"],
        report["documents"][0]["admitted_claims"]
    );

    // Extract-only uses the same streaming path but must leave all configured
    // durable stores byte-for-byte unchanged.
    std::env::set_var("OPENROUTER_API_KEY", "ctxql-hermetic-fake-provider-key");
    let mut config = fixture.config().unwrap();
    let acquisition = config.acquisition.as_mut().unwrap();
    acquisition.window.mode = "always".into();
    acquisition.window.target_bytes = 56;
    acquisition.window.max_bytes = 64;
    acquisition.window.overlap_bytes = 0;
    // Drain admission clients' asynchronous WAL cleanup before measuring the
    // separate extract-only operation; no store files are excluded.
    wal_cleanup::wait_for_wal_cleanup(fixture.root(), std::time::Duration::from_secs(5)).await;
    let before = durable_snapshot(fixture.root());
    let extracted = ingest(
        config,
        SourceTarget::LocalFile(
            fixture
                .root()
                .join("documents/streaming.txt")
                .canonicalize()
                .unwrap(),
        ),
        IngestMode::ExtractOnly,
        OntologyMode::Soft,
        2 * 1024 * 1024,
        None,
        None,
        None,
        CancellationToken::default(),
    )
    .await
    .unwrap();
    let extracted = serde_json::to_value(extracted).unwrap();
    assert_eq!(extracted["admitted_claim_count"], 0);
    assert_eq!(before, durable_snapshot(fixture.root()));
}

fn mutate_capture(
    capture: &serde_json::Value,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> Vec<u8> {
    let mut value = capture.clone();
    mutate(&mut value);
    serde_json::to_vec(&value).unwrap()
}

fn assert_capture_rejected(bytes: Vec<u8>, expected: &str) {
    let error = cdb_service::ingest::verify_capture_manifest_bytes(&bytes).unwrap_err();
    let diagnostic = format!("{error:?}");
    assert!(
        diagnostic.contains(expected),
        "expected diagnostic {expected:?}, got {diagnostic}"
    );
}

fn durable_snapshot(root: &Path) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for name in ["semantic", "control", "projection", "sources"] {
        collect(root, &root.join(name), &mut result);
    }
    result.sort_by(|left, right| left.0.cmp(&right.0));
    result
}

fn collect(root: &Path, path: &Path, output: &mut Vec<(String, String)>) {
    if path.is_dir() {
        let mut entries = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        for entry in entries {
            collect(root, &entry, output);
        }
    } else if path.is_file() {
        output.push((
            path.strip_prefix(root).unwrap().display().to_string(),
            cdb_core::id::ContentHash::of_bytes(&fs::read(path).unwrap())
                .as_str()
                .to_owned(),
        ));
    }
}

fn install_streaming_fake(root: &Path) {
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
        with (root / "pi-prompts.jsonl").open("a") as log:
            log.write(json.dumps(prompt, separators=(",", ":")) + "\n")
        window = next(item for item in prompt["ranges"] if item["kind"] == "window")
        handles = prompt["document_entity_handles"]["entries"]
        if not handles:
            text = f"ENTITY:\nId: agreement\nName: Orion\nKnown entity: none\nEVIDENCE:\nRange: {window['range']}\nOccurrence: 0\nQuote: Orion\n---"
        else:
            text = f"ENTITY:\nId: borrower\nName: Acme\nKnown entity: none\nEVIDENCE:\nRange: {window['range']}\nOccurrence: 0\nQuote: Acme\n---\nCLAIM:\nKind: relation\nSubject: document {handles[0]['handle']}\nPredicate: has borrower\nPredicate note:\nPredicate selected: 0\nObject: local borrower\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\nEVIDENCE:\nRange: {window['range']}\nOccurrence: 0\nQuote: Orion borrows from Acme\n---"
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
