use cdb_backend_fluree::{
    official_bootstrap::{
        ACQUISITION_V2_FIXTURE_ACTION, ACQUISITION_V2_FIXTURE_LEDGER,
        ACQUISITION_V2_FIXTURE_PRINCIPAL,
    },
    runs::Operation,
};
use cdb_core::id::{ContentHash, JobId};
use cdb_provider_pi::cancel::CancellationToken;
use cdb_service::{
    acquisition_inspection::AuthorizedAcquisition,
    acquisition_v2_fixture::AcquisitionV2Fixture,
    auth,
    config::AcquisitionAssertionPolicy,
    ingest::{ingest, IngestMode, IngestWait, OntologyMode},
    source_target::SourceTarget,
};
use fluree_db_api::FlureeBuilder;
use std::{
    fs,
    path::{Path, PathBuf},
};

const POLICY_GRAPH: &str = "urn:ctxql:a2:policy";

#[test]
fn converted_pdf_replay_is_converter_free_and_ephemeral_when_requested() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "converted_pdf_replay_child",
            "--test-threads=1",
        ])
        .env("RUST_MIN_STACK", "33554432")
        .env("OPENROUTER_API_KEY", "ctxql-hermetic-fake-provider-key")
        .status()
        .unwrap();
    assert!(status.success(), "serial PDF replay child failed");
}

#[tokio::test]
#[ignore = "run only through the serial environment wrapper"]
async fn converted_pdf_replay_child() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let converter = fixture.root().join("fake-pdf-converter.py");
    let converter_count = fixture.root().join("converter-invocations");
    fs::write(&converter_count, b"0\n").unwrap();
    let converted_text = "Orion is a written agreement under which Acme Ltd borrows GBP 1000.\nOrion was executed on 2022-12-06.\nOrion agreement date: 2022-12-06.\n";
    let converter_bytes = format!(
        "#!/usr/bin/env python3\nimport pathlib,sys\np=pathlib.Path({:?})\np.write_text(str(int(p.read_text().strip())+1)+'\\n')\nsys.stdin.buffer.read()\nsys.stdout.write({converted_text:?})\n",
        converter_count.display().to_string()
    );
    fs::write(&converter, converter_bytes.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&converter, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let executable_hash = ContentHash::of_bytes(converter_bytes.as_bytes());
    let mut config_text = fs::read_to_string(fixture.config_path()).unwrap();
    config_text.push_str(&format!(
        "\n[acquisition.converters.pdf]\ncommand = {:?}\nversion = \"fake-pdf-v1\"\nexecutable-hash = {:?}\narguments = []\nnormalization = \"none\"\n",
        converter.display().to_string(), executable_hash.as_str()
    ));
    fs::write(fixture.config_path(), config_text).unwrap();

    let document = fixture
        .write_document("stored-replay.pdf", b"%PDF immutable original")
        .unwrap();
    fixture
        .set_pi_response(include_str!(
            "../../../fixtures/conformance/p6/ontology-guided/a2-proposals-v2.json"
        ))
        .unwrap();
    let report = ingest(
        fixture.config().unwrap(),
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
    let report = serde_json::to_value(report).unwrap();
    assert_eq!(read_count(&converter_count), 1);
    assert_eq!(fixture.pi_invocations().unwrap(), 1);
    let job = JobId::new(report["documents"][0]["job_id"].as_str().unwrap()).unwrap();

    install_explicit_allow(fixture.root()).await;
    use_view_action(&fixture);
    let token = fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    let access = AuthorizedAcquisition::open_authenticated(
        fixture.config().unwrap(),
        &token,
        Operation::Replay,
        auth::Operation::Replay,
    )
    .await
    .unwrap();
    let inspection = access.inspect(&token, job).await.unwrap();
    let capture_root = ContentHash::parse(
        inspection
            .field("artifacts")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .find(|value| {
                value.field("artifact_kind").unwrap().as_str().unwrap() == "evaluation_outcomes"
            })
            .unwrap()
            .field("context_root")
            .unwrap()
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let before_sources = tree_image(&fixture.root().join("sources"));
    let before_work = tree_image(&fixture.root().join("control/acquisition-work-v2"));
    let ephemeral = access
        .replay_ephemeral(
            &token,
            capture_root.clone(),
            OntologyMode::Soft,
            AcquisitionAssertionPolicy::Accepted,
        )
        .await
        .unwrap();
    assert!(ephemeral.field("ephemeral").unwrap().as_bool().unwrap());
    assert_eq!(
        ephemeral
            .field("report")
            .unwrap()
            .field("admitted_claim_count")
            .unwrap()
            .u64()
            .unwrap(),
        0
    );
    assert_eq!(tree_image(&fixture.root().join("sources")), before_sources);
    assert_eq!(
        tree_image(&fixture.root().join("control/acquisition-work-v2")),
        before_work
    );
    assert_eq!(
        read_count(&converter_count),
        1,
        "ephemeral replay called converter"
    );
    assert_eq!(
        fixture.pi_invocations().unwrap(),
        1,
        "ephemeral replay called provider"
    );

    let durable = access
        .replay(
            &token,
            capture_root,
            OntologyMode::Soft,
            AcquisitionAssertionPolicy::EvidenceOnly,
            IngestWait::Admitted,
        )
        .await
        .unwrap();
    assert!(!durable.field("ephemeral").unwrap().as_bool().unwrap());
    assert_eq!(
        read_count(&converter_count),
        1,
        "durable replay called converter"
    );
    assert_eq!(
        fixture.pi_invocations().unwrap(),
        1,
        "durable replay called provider"
    );
    access.shutdown().await.unwrap();
}

fn read_count(path: &Path) -> u64 {
    fs::read_to_string(path).unwrap().trim().parse().unwrap()
}

fn tree_image(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn visit(root: &Path, at: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        if !at.exists() {
            return;
        }
        let mut entries = fs::read_dir(at)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                visit(root, &path, out);
            } else {
                out.push((
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                ));
            }
        }
    }
    let mut out = Vec::new();
    visit(root, root, &mut out);
    out
}

fn use_view_action(fixture: &AcquisitionV2Fixture) {
    let config = fs::read_to_string(fixture.config_path()).unwrap();
    fs::write(
        fixture.config_path(),
        config.replace(
            &format!("action = \"{ACQUISITION_V2_FIXTURE_ACTION}\""),
            "action = \"https://ns.flur.ee/db#view\"",
        ),
    )
    .unwrap();
}

async fn install_explicit_allow(root: &Path) {
    let turtle = format!(
        r#"@prefix f: <https://ns.flur.ee/db#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
GRAPH <{POLICY_GRAPH}> {{
  <{ACQUISITION_V2_FIXTURE_PRINCIPAL}> f:policyClass <urn:ctxql:a2:PublicPolicy> .
  <urn:ctxql:a2:pdf-replay-allow> rdf:type f:AccessPolicy, <urn:ctxql:a2:PublicPolicy> ;
    f:action f:view ; f:allow true .
}}"#
    );
    let fluree = FlureeBuilder::file(root.join("semantic").to_string_lossy().into_owned())
        .without_indexing()
        .build()
        .unwrap();
    let ledger = fluree.ledger(ACQUISITION_V2_FIXTURE_LEDGER).await.unwrap();
    fluree
        .stage_owned(ledger)
        .upsert_turtle(&turtle)
        .execute()
        .await
        .unwrap();
}
