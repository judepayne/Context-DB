use cdb_service::config::*;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
#[test]
fn documented_chat_limits_match_current_defaults() {
    let example: toml::Value =
        toml::from_str(include_str!("../../../fixtures/examples/chat/cdb.toml")).unwrap();
    let shown: ChatLimits = example["chat"]["limits"].clone().try_into().unwrap();
    let defaults = ChatLimits::default();
    assert_eq!(shown.turn_seconds, defaults.turn_seconds);
    assert_eq!(shown.max_reported_tokens, defaults.max_reported_tokens);
    assert_eq!(shown.max_work, defaults.max_work);
    assert_eq!(
        shown.max_reported_cost_micro_usd,
        defaults.max_reported_cost_micro_usd
    );
    assert_eq!(shown.host_call_seconds, defaults.host_call_seconds);
}

fn text() -> String {
    r#"schema = "ctxql-instance/v1"
projection = "projection"
credential-file = "credentials.json"
source-root = "sources"
[authority]
path = "authority"
ledger = "main"
backend = "urn:backend:test"
authority = "urn:authority:test"
graph = "urn:graph:test"
"#
    .into()
}
#[test]
fn config_strict_and_relative() {
    let c = InstanceConfig::parse(&text(), Path::new("/instance/cdb.toml")).unwrap();
    assert!(c.role == InstanceRole::Replayable);
    assert_eq!(
        c.authority_options().unwrap().path,
        Path::new("/instance/authority")
    );
    let p = c.projection_binding().unwrap();
    assert_eq!(p.path, Path::new("/instance/projection"));
    assert!(
        !p.backend.as_str().is_empty()
            && !p.authority.as_str().is_empty()
            && !p.graph.as_str().is_empty()
    );
    assert!(c.required_default_config().is_err());
    assert_eq!(c.limits.deadline(), Duration::from_secs(30));
    assert_eq!(c.limits.session_ttl(), Duration::from_secs(300));
    for (index, bad) in [
        format!("unknown = 1\n{}", text()),
        text().replace("ctxql-instance/v1", "ctxql-instance/v3"),
        format!("bind = \"0.0.0.0:8080\"\n{}", text()),
        format!("{}\n[limits]\nconcurrency = 1.0", text()),
        format!("{}\n[limits]\nconcurrency = 0", text()),
        format!("{}\n[limits]\nsession_ttl_seconds = 301", text()),
        format!(
            "{}\n[default-config]\niri = 1.0\nversion = \"v1\"\nhash = \"x\"",
            text()
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            InstanceConfig::parse(&bad, Path::new("/instance/cdb.toml")).is_err(),
            "bad configuration {index} was accepted"
        );
    }
    assert!(InstanceConfig::parse(&text(), Path::new("cdb.toml")).is_err());
}
fn v3_text() -> String {
    r#"schema = "ctxql-instance/v3"
projection = "projection"
credential-file = "credentials.json"
source-root = "sources"
[semantic]
path = "semantic"
ledger = "semantic:main"
backend = "urn:backend:semantic"
authority = "urn:authority:semantic"
graph = "urn:graph:semantic"
[control]
path = "control"
ledger = "control:main"
backend = "urn:backend:control"
authority = "urn:authority:control"
graph = "urn:graph:control"
"#
    .into()
}

#[test]
fn v3_requires_disjoint_semantic_and_control_capabilities() {
    let c = InstanceConfig::parse(&v3_text(), Path::new("/instance/cdb.toml")).unwrap();
    assert_eq!(
        c.authority_options().unwrap().path,
        Path::new("/instance/control")
    );
    let (semantic_path, semantic) = c.semantic_binding().unwrap();
    assert_eq!(semantic_path, Path::new("/instance/semantic"));
    assert_eq!(semantic.ledger.as_str(), "semantic:main");

    let with_legacy = format!(
        "{}\n[authority]\npath=\"legacy\"\nledger=\"legacy:main\"\nbackend=\"legacy\"\nauthority=\"legacy\"\ngraph=\"legacy\"\n",
        v3_text()
    );
    assert!(InstanceConfig::parse(&with_legacy, Path::new("/instance/cdb.toml")).is_err());
    let same_path = v3_text().replace("path = \"control\"", "path = \"semantic\"");
    assert!(InstanceConfig::parse(&same_path, Path::new("/instance/cdb.toml")).is_err());
    let aliased = v3_text()
        .replace("urn:backend:control", "urn:backend:semantic")
        .replace("urn:authority:control", "urn:authority:semantic")
        .replace("control:main", "semantic:main")
        .replace("urn:graph:control", "urn:graph:semantic");
    assert!(InstanceConfig::parse(&aliased, Path::new("/instance/cdb.toml")).is_err());
    assert!(InstanceConfig::parse(
        &v3_text().replace("ctxql-instance/v3", "ctxql-instance/v2"),
        Path::new("/instance/cdb.toml")
    )
    .is_err());
}

#[test]
fn v3_chat_read_configuration_is_closed_and_acquisition_independent() {
    let chat = format!(
        r#"{}
[chat]
pi-command = "/opt/homebrew/bin/pi"
pi-bundle = "pi-bundle"
chat_model = "openrouter/deepseek/deepseek-v4.1-flash"
thinking = "high"
[chat.query-config]
iri = "urn:ctxql:chat-config"
version = "1"
hash = "sha256:{}"
"#,
        v3_text(),
        "a".repeat(64)
    );
    let parse = || InstanceConfig::parse(&chat, Path::new("/instance/cdb.toml")).unwrap();
    let parsed = parse();
    assert!(parsed.acquisition.is_none());
    let configured = parsed.chat.as_ref().unwrap();
    assert_eq!(configured.pi_bundle, Path::new("/instance/pi-bundle"));
    assert!(configured.pi_session_log_dir.is_none());
    assert_eq!(configured.limits.max_nodes, 50);
    assert_eq!(configured.limits.max_input_bytes, 8192);
    assert_eq!(configured.limits.max_turns, 20);
    assert_eq!(configured.limits.max_model_rounds, 100);
    assert_eq!(configured.limits.turn_seconds, 300);
    assert_eq!(configured.limits.shutdown_seconds, 2);
    assert_eq!(configured.limits.max_answer_bytes, 65_536);
    assert_eq!(configured.limits.max_context_bytes, 512 * 1024);
    assert_eq!(configured.limits.max_rpc_record_bytes, 1_048_576);
    assert_eq!(configured.limits.max_rpc_queue_bytes, 2_097_152);
    assert_eq!(configured.limits.max_rpc_events_per_turn, 16_384);
    assert_eq!(configured.limits.max_reported_tokens, 1_000_000);
    assert_eq!(configured.limits.max_reported_cost_micro_usd, 5_000_000);
    parsed.validate_runtime().unwrap();

    for protected in [
        &parsed.source_root,
        &parsed.projection,
        &parsed.semantic.as_ref().unwrap().path,
        &parsed.control.as_ref().unwrap().path,
    ] {
        let mut nested = parse();
        nested.chat.as_mut().unwrap().pi_bundle = protected.join("assets");
        assert!(nested.validate_runtime().is_err());
        let mut aliased = parse();
        aliased.chat.as_mut().unwrap().pi_bundle = protected.join("child/..");
        assert!(aliased.validate_runtime().is_err());
    }
    let mut tighter_service = parse();
    tighter_service.limits.deadline_seconds = 1;
    tighter_service.limits.max_work = 1;
    tighter_service.validate_runtime().unwrap(); // Reads clamp defaults to service ceilings.
    let mut nested_stores = parse();
    nested_stores.source_root = nested_stores.projection.join("sources");
    assert!(nested_stores.validate_runtime().is_err());
    #[cfg(unix)]
    {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().canonicalize().unwrap();
        std::fs::create_dir(dir.join("assets")).unwrap();
        std::os::unix::fs::symlink(dir.join("assets"), dir.join("alias")).unwrap();
        let mut symlinked = parse();
        symlinked.chat.as_mut().unwrap().pi_bundle = dir.join("alias");
        assert!(symlinked.validate_runtime().is_err());
    }

    let v1 = chat.replace("ctxql-instance/v3", "ctxql-instance/v1");
    assert!(InstanceConfig::parse(&v1, Path::new("/instance/cdb.toml")).is_err());
    for obsolete in ["model", "chat-model"] {
        assert!(InstanceConfig::parse(
            &chat.replace("chat_model", obsolete),
            Path::new("/instance/cdb.toml")
        )
        .is_err());
    }
    assert!(InstanceConfig::parse(
        &chat.replace("thinking =", "unknown-thinking ="),
        Path::new("/instance/cdb.toml")
    )
    .is_err());
}

#[test]
fn pi_session_logging_is_independently_opt_in_and_path_checked() {
    let chat = format!(
        r#"{}
[chat]
pi-command = "/opt/homebrew/bin/pi"
pi-bundle = "pi-bundle"
pi-session-log-dir = "chat-logs"
chat_model = "openrouter/deepseek/deepseek-v4.1-flash"
thinking = "high"
[chat.query-config]
iri = "urn:ctxql:chat-config"
version = "1"
hash = "sha256:{}"
"#,
        v3_text(),
        "a".repeat(64)
    );
    let parsed = InstanceConfig::parse(&chat, Path::new("/instance/cdb.toml")).unwrap();
    assert_eq!(
        parsed.chat.as_ref().unwrap().pi_session_log_dir.as_deref(),
        Some(Path::new("/instance/chat-logs"))
    );
    assert!(parsed.acquisition.is_none());
    parsed.validate_runtime().unwrap();

    let extraction = v4_text().replace(
        "pi-bundle = \"pi-bundle\"",
        "pi-bundle = \"pi-bundle\"\npi-session-log-dir = \"extraction-logs\"",
    );
    let parsed = InstanceConfig::parse(&extraction, Path::new("/instance/cdb.toml")).unwrap();
    assert_eq!(
        parsed
            .acquisition
            .as_ref()
            .unwrap()
            .pi_session_log_dir
            .as_deref(),
        Some(Path::new("/instance/extraction-logs"))
    );
    assert!(parsed.chat.is_none());
    parsed.validate_runtime().unwrap();

    for field in ["pi-session-log-dir = \"\"", "pi-session-logs = \"logs\""] {
        let invalid = chat.replace("pi-session-log-dir = \"chat-logs\"", field);
        assert!(InstanceConfig::parse(&invalid, Path::new("/instance/cdb.toml")).is_err());
    }
    let mut runtime = InstanceConfig::parse(&chat, Path::new("/instance/cdb.toml")).unwrap();
    runtime.chat.as_mut().unwrap().pi_session_log_dir = Some(PathBuf::from("relative"));
    assert!(runtime.validate_runtime().is_err());
    let overlapping = chat.replace(
        "pi-session-log-dir = \"chat-logs\"",
        "pi-session-log-dir = \"semantic\"",
    );
    assert!(InstanceConfig::parse(&overlapping, Path::new("/instance/cdb.toml")).is_err());
}

#[test]
fn either_pi_log_destination_is_separate_from_all_instance_resources() {
    let config_path = Path::new("/instance/cdb.toml");
    let base = format!(
        r#"{}
[chat]
pi-command = "/opt/homebrew/bin/pi"
pi-bundle = "chat-assets"
chat_model = "openrouter/deepseek/deepseek-v4.1-flash"
thinking = "high"
[chat.query-config]
iri = "urn:ctxql:chat-config"
version = "1"
hash = "sha256:{}"
[chat.ontology]
bootstrap-path = "chat-ontology"
receipt-hash = "sha256:{}"
"#,
        v4_text().replace(
            "pi-bundle = \"pi-bundle\"",
            "pi-bundle = \"extractor-assets\"\nontology-ledger-path = \"extractor-ontology\""
        ),
        "a".repeat(64),
        "b".repeat(64),
    );
    InstanceConfig::parse(&base, config_path)
        .unwrap()
        .validate_runtime()
        .unwrap();
    for producer in ["chat", "acquisition"] {
        for protected in [
            "semantic",
            "control",
            "projection",
            "sources",
            "documents",
            "extractor-assets",
            "extractor-ontology",
            "chat-assets",
            "chat-ontology",
        ] {
            for destination in [protected.to_owned(), format!("{protected}/logs")] {
                let configured = base.replace(
                    &format!("[{producer}]"),
                    &format!("[{producer}]\npi-session-log-dir = \"{destination}\""),
                );
                assert!(
                    InstanceConfig::parse(&configured, config_path).is_err(),
                    "{producer}: {destination}"
                );
                let mut runtime = InstanceConfig::parse(&base, config_path).unwrap();
                let destination = Some(Path::new("/instance").join(destination));
                if producer == "chat" {
                    runtime.chat.as_mut().unwrap().pi_session_log_dir = destination;
                } else {
                    runtime.acquisition.as_mut().unwrap().pi_session_log_dir = destination;
                }
                assert!(
                    runtime.validate_runtime().is_err(),
                    "runtime {producer}: {protected}"
                );
            }
        }
        let parent = base.replace(
            &format!("[{producer}]"),
            &format!("[{producer}]\npi-session-log-dir = \"/instance\""),
        );
        assert!(InstanceConfig::parse(&parent, config_path).is_err());
    }
    // Independent producer logs may share a private destination; per-process
    // directories/files remain unique and neither is an ingestible source.
    let shared = base
        .replace("[chat]", "[chat]\npi-session-log-dir = \"logs\"")
        .replace(
            "[acquisition]",
            "[acquisition]\npi-session-log-dir = \"logs\"",
        );
    InstanceConfig::parse(&shared, config_path)
        .unwrap()
        .validate_runtime()
        .unwrap();
}

#[test]
fn chat_unsafe_direct_projection_is_default_off_and_strict_boolean() {
    let chat = format!(
        r#"{}
[chat]
pi-command = "/opt/homebrew/bin/pi"
pi-bundle = "pi-bundle"
chat_model = "openrouter/deepseek/deepseek-v4.1-flash"
thinking = "high"
[chat.query-config]
iri = "urn:ctxql:chat-config"
version = "1"
hash = "sha256:{}"
"#,
        v3_text(),
        "a".repeat(64)
    );
    let parsed = InstanceConfig::parse(&chat, Path::new("/instance/cdb.toml")).unwrap();
    assert!(!parsed.chat.unwrap().unsafe_direct_projection);

    let explicitly_unsafe = chat.replace("[chat]", "[chat]\nunsafe-direct-projection = true");
    let parsed =
        InstanceConfig::parse(&explicitly_unsafe, Path::new("/instance/cdb.toml")).unwrap();
    assert!(parsed.chat.unwrap().unsafe_direct_projection);

    let wrong_type = chat.replace("[chat]", "[chat]\nunsafe-direct-projection = \"true\"");
    assert!(InstanceConfig::parse(&wrong_type, Path::new("/instance/cdb.toml")).is_err());
}

#[test]
fn chat_phase3_limits_are_finite_and_runtime_checked() {
    let chat = format!(
        r#"{}
[chat]
pi-command = "/opt/homebrew/bin/pi"
pi-bundle = "pi-bundle"
chat_model = "openrouter/deepseek/deepseek-v4.1-flash"
thinking = "high"
[chat.query-config]
iri = "urn:ctxql:chat-config"
version = "1"
hash = "sha256:{}"
"#,
        v3_text(),
        "a".repeat(64)
    );
    // Conversation retention is configurable above its default, up to 64 MiB.
    for bytes in [1, 512 * 1024, 8 * 1024 * 1024, 64 * 1024 * 1024] {
        let configured = format!("{chat}\n[chat.limits]\nmax-context-bytes = {bytes}\n");
        let parsed = InstanceConfig::parse(&configured, Path::new("/instance/cdb.toml")).unwrap();
        assert_eq!(
            parsed.chat.as_ref().unwrap().limits.max_context_bytes,
            bytes
        );
        parsed.validate_runtime().unwrap();
    }
    for bytes in [0, 64 * 1024 * 1024 + 1] {
        let configured = format!("{chat}\n[chat.limits]\nmax-context-bytes = {bytes}\n");
        assert!(InstanceConfig::parse(&configured, Path::new("/instance/cdb.toml")).is_err());
        let mut parsed = InstanceConfig::parse(&chat, Path::new("/instance/cdb.toml")).unwrap();
        parsed.chat.as_mut().unwrap().limits.max_context_bytes = bytes;
        assert!(parsed.validate_runtime().is_err());
    }
    let mutations: [fn(&mut ChatLimits); 11] = [
        |v| v.max_input_bytes = 8193,
        |v| v.max_turns = 21,
        |v| v.max_model_rounds = 101,
        |v| v.turn_seconds = 301,
        |v| v.shutdown_seconds = 3,
        |v| v.max_answer_bytes = 65_537,
        |v| v.max_rpc_record_bytes = 1_048_577,
        |v| v.max_rpc_queue_bytes = 2_097_153,
        |v| v.max_rpc_events_per_turn = 16_385,
        |v| v.max_reported_tokens = 1_000_001,
        |v| v.max_reported_cost_micro_usd = 5_000_001,
    ];
    for mutate in mutations {
        let mut parsed = InstanceConfig::parse(&chat, Path::new("/instance/cdb.toml")).unwrap();
        mutate(&mut parsed.chat.as_mut().unwrap().limits);
        assert!(parsed.validate_runtime().is_err());
    }
}

fn v4_text() -> String {
    format!(
        r#"{}
[acquisition]
access-mode = "direct"
claims-graph = "urn:ctxql:claims"
principal = "urn:ctxql:trusted-acquisition"
action = "https://ns.flur.ee/db#modify"
pi-command = "/opt/homebrew/bin/pi"
pi-bundle = "pi-bundle"
extractor_model = "openrouter/deepseek/deepseek-v4.1-flash"
thinking = "high"
batch-size = 2
max-source-bytes = 1048576
max-document-bytes = 524288
max-folder-entries = 100
provider-timeout-seconds = 120
projection-timeout-seconds = 30
control-journal-bytes = 1048576
ontology-profile = "ctxql-ontology-profile/fluree-4.2-603974fad5c13efed9d147d214d613849fb43c73/v3-supported-subset"
ontology-catalog-root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
allowed-local-roots = ["documents"]
[acquisition.window]
mode = "auto"
target-bytes = 4096
max-bytes = 8192
overlap-bytes = 256
"#,
        v3_text().replace("ctxql-instance/v3", "ctxql-instance/v4")
    )
}

fn graph_workspace_text(explicit_query: bool) -> String {
    let mut base = v4_text()
        .replace(
            "[acquisition]",
            &format!(
                "{}[acquisition]\nprotocol = \"ontology-v2\"\nreview-graph = \"urn:ctxql:review\"",
                if explicit_query {
                    "".to_owned()
                } else {
                    format!(
                        "[default-config]\niri = \"urn:ctxql:query-config\"\nversion = \"1\"\nhash = \"sha256:{}\"\n",
                        "b".repeat(64)
                    )
                }
            ),
        )
        .replace(
            cdb_core::recording_v4::ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID,
            cdb_core::recording_v5::CURRENT_ACQUISITION_PROFILE_ID,
        )
        .replace("mode = \"auto\"", "mode = \"off\"");
    base.push_str(
        r#"[acquisition.graph-workspace]
query-timeout-seconds = 10
max-nodes = 50
max-claims = 100
max-live-graphs = 3
max-tool-calls = 40
max-graph-queries = 12
max-request-bytes = 32768
max-response-bytes = 65536
max-aggregate-bytes = 1048576
max-state-bytes = 2097152
max-context-bytes = 524288
reserved-final-output-bytes = 65536
reserved-tool-result-bytes = 262144
"#,
    );
    if explicit_query {
        base.push_str(&format!(
            r#"[acquisition.graph-workspace.query-config]
iri = "urn:ctxql:query-config"
version = "1"
hash = "sha256:{}"
"#,
            "c".repeat(64)
        ));
    }
    base
}

#[test]
fn graph_workspace_config_is_closed_bounded_and_requires_whole_document_v2() {
    let path = Path::new("/instance/cdb.toml");
    let absent = InstanceConfig::parse(&v4_text(), path).unwrap();
    assert!(absent.acquisition.unwrap().graph_workspace.is_none());

    let default_bound = InstanceConfig::parse(&graph_workspace_text(false), path).unwrap();
    let graph = default_bound
        .acquisition
        .as_ref()
        .unwrap()
        .graph_workspace
        .as_ref()
        .unwrap();
    assert!(graph.query_config.is_none());
    assert_eq!((graph.max_nodes, graph.max_claims), (50, 100));
    assert!(InstanceConfig::parse(&graph_workspace_text(true), path).is_ok());

    let base = graph_workspace_text(false);
    for bad in [
        base.replace(
            "reserved-tool-result-bytes = 262144",
            "reserved-tool-result-bytes = 262144\nunknown = 1",
        ),
        base.replace("protocol = \"ontology-v2\"\n", ""),
        base.replace("mode = \"off\"", "mode = \"auto\""),
        base.replace("max-nodes = 50", "max-nodes = 0"),
        base.replace("max-nodes = 50", "max-nodes = 51"),
        base.replace("max-claims = 100", "max-claims = 101"),
        base.replace("max-live-graphs = 3", "max-live-graphs = 4"),
        base.replace("max-tool-calls = 40", "max-tool-calls = 41"),
        base.replace("max-graph-queries = 12", "max-graph-queries = 41"),
        base.replace("max-request-bytes = 32768", "max-request-bytes = 32769"),
        base.replace("max-response-bytes = 65536", "max-response-bytes = 65537"),
        base.replace(
            "max-aggregate-bytes = 1048576",
            "max-aggregate-bytes = 1048577",
        ),
        base.replace("max-state-bytes = 2097152", "max-state-bytes = 2097153"),
        base.replace("max-context-bytes = 524288", "max-context-bytes = 524289"),
        base.replace(
            "reserved-tool-result-bytes = 262144",
            "reserved-tool-result-bytes = 1048577",
        ),
        base.replace(
            "reserved-final-output-bytes = 65536",
            "reserved-final-output-bytes = 400000",
        )
        .replace(
            "reserved-tool-result-bytes = 262144",
            "reserved-tool-result-bytes = 200000",
        ),
        base.replace("query-timeout-seconds = 10", "query-timeout-seconds = 31"),
        base.replace("query-timeout-seconds = 10", "query-timeout-seconds = 121"),
        base.replace(
            "query-timeout-seconds = 10",
            "profile-selector = \"loan\"\nquery-timeout-seconds = 10",
        ),
        graph_workspace_text(true).replace(
            "[acquisition.graph-workspace.query-config]",
            "[acquisition.graph-workspace.bad-query-config]",
        ),
    ] {
        assert!(
            InstanceConfig::parse(&bad, path).is_err(),
            "accepted: {bad}"
        );
    }

    let no_default = base
        .replace(
            &format!(
                "[default-config]\niri = \"urn:ctxql:query-config\"\nversion = \"1\"\nhash = \"sha256:{}\"\n",
                "b".repeat(64)
            ),
            "",
        );
    assert!(InstanceConfig::parse(&no_default, path).is_err());

    let mut mutated = InstanceConfig::parse(&base, path).unwrap();
    mutated
        .acquisition
        .as_mut()
        .unwrap()
        .graph_workspace
        .as_mut()
        .unwrap()
        .max_nodes = 51;
    assert!(mutated.validate_runtime().is_err());
}

#[test]
fn graph_workspace_profile_binding_is_paired_and_validated() {
    let path = Path::new("/instance/cdb.toml");
    let mut with_profile = graph_workspace_text(false).replace(
        "query-timeout-seconds = 10",
        "profile-selector = \"loan\"\nquery-timeout-seconds = 10",
    );
    with_profile.push_str(&format!(
        r#"[acquisition.graph-workspace.profile]
iri = "urn:ctxql:profile"
version = "1"
hash = "sha256:{}"
"#,
        "d".repeat(64)
    ));
    assert!(InstanceConfig::parse(&with_profile, path).is_ok());
    let missing_selector = with_profile.replace("profile-selector = \"loan\"\n", "");
    assert!(InstanceConfig::parse(&missing_selector, path).is_err());
}

#[test]
fn ontology_v2_requires_current_uncertified_acquisition_identity() {
    let base = v4_text()
        .replace(
            "[acquisition]",
            "[acquisition]\nprotocol = \"ontology-v2\"\nreview-graph = \"urn:ctxql:review\"",
        )
        .replace(
            "ontology-catalog-root =",
            "ontology-ledger-path = \"fibo\"\nontology-catalog-root =",
        );
    assert!(InstanceConfig::parse(&base, Path::new("/instance/cdb.toml")).is_err());
    let current = base.replace(
        cdb_core::recording_v4::ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID,
        cdb_core::recording_v5::CURRENT_ACQUISITION_PROFILE_ID,
    );
    let parsed = InstanceConfig::parse(&current, Path::new("/instance/cdb.toml")).unwrap();
    assert_eq!(
        parsed.acquisition.unwrap().ontology_profile,
        cdb_core::recording_v5::CURRENT_ACQUISITION_PROFILE_ID
    );
}

#[test]
fn v4_closes_trusted_acquisition_configuration() {
    let config = InstanceConfig::parse(&v4_text(), Path::new("/instance/cdb.toml")).unwrap();
    let acquisition = config.acquisition.as_ref().unwrap();
    assert_eq!(acquisition.extractor_model, cdb_provider_pi::MODEL);
    assert_eq!(acquisition.batch_size, 2);
    assert_eq!(
        acquisition.ontology_profile,
        cdb_core::recording_v4::ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID
    );
    assert_eq!(acquisition.pi_bundle, Path::new("/instance/pi-bundle"));
    let direct = InstanceConfig::parse(
        &v4_text().replace(
            "ontology-catalog-root =",
            "ontology-ledger-path = \"fibo\"\nontology-catalog-root =",
        ),
        Path::new("/instance/cdb.toml"),
    )
    .unwrap();
    assert_eq!(
        direct.acquisition.unwrap().ontology_ledger_path.as_deref(),
        Some(Path::new("/instance/fibo"))
    );
    assert_eq!(
        acquisition.allowed_local_roots,
        [Path::new("/instance/documents")]
    );
    assert!(InstanceConfig::parse(
        &v4_text().replace(
            "provider-timeout-seconds = 120",
            "provider-timeout-seconds = 999999"
        ),
        Path::new("/instance/cdb.toml")
    )
    .is_err());
    let mut mutated = InstanceConfig::parse(&v4_text(), Path::new("/instance/cdb.toml")).unwrap();
    mutated.acquisition.as_mut().unwrap().max_source_bytes = usize::MAX;
    assert!(mutated.validate_runtime().is_err());
    assert!(InstanceConfig::parse(
        &v4_text().replace("thinking = \"high\"", "thinking = \"off\""),
        Path::new("/instance/cdb.toml")
    )
    .is_err());
    for obsolete in ["model", "extractor-model"] {
        assert!(InstanceConfig::parse(
            &v4_text().replace("extractor_model", obsolete),
            Path::new("/instance/cdb.toml")
        )
        .is_err());
    }
    assert!(InstanceConfig::parse(
        &v4_text().replace("v3-supported-subset", "v3"),
        Path::new("/instance/cdb.toml")
    )
    .is_err());
    assert!(InstanceConfig::parse(
        &v4_text().replace("batch-size = 2", "batch-size = 4"),
        Path::new("/instance/cdb.toml")
    )
    .is_err());
    assert!(InstanceConfig::parse(
        &v4_text().replace("documents", "sources"),
        Path::new("/instance/cdb.toml")
    )
    .is_err());
}

fn table() -> CredentialTable {
    CredentialTable {
        schema: "ctxql-credentials/v1".into(),
        entries: vec![CredentialEntry {
            digest: format!("sha256:{}", "a".repeat(64)),
            principal: "urn:principal:test".into(),
            enabled: true,
            expires_at: Some("2099-01-01T00:00:00Z".into()),
            capabilities: vec!["query".into()],
        }],
    }
}
#[test]
fn v2_lifetimes_are_explicitly_bounded_without_changing_defaults() {
    let base = text().replace("ctxql-instance/v1", "ctxql-instance/v2");
    let defaults = InstanceConfig::parse(&base, Path::new("/instance/cdb.toml")).unwrap();
    assert_eq!(defaults.limits.deadline(), Duration::from_secs(30));
    assert_eq!(defaults.limits.session_ttl(), Duration::from_secs(300));
    let long = InstanceConfig::parse(
        &(base.clone() + "\n[limits]\ndeadline_seconds = 86400\nsession_ttl_seconds = 86400\n"),
        Path::new("/instance/cdb.toml"),
    )
    .unwrap();
    assert_eq!(long.limits.deadline(), Duration::from_secs(86_400));
    assert_eq!(long.limits.session_ttl(), Duration::from_secs(86_400));
    assert!(InstanceConfig::parse(
        &(base + "\n[limits]\nsession_ttl_seconds = 86401\n"),
        Path::new("/instance/cdb.toml"),
    )
    .is_err());
}

#[test]
fn exact_limits_and_caps() {
    for (key, cap) in [
        ("max_body_bytes", 16 * 1024 * 1024),
        ("concurrency", 256),
        ("connections", 1024),
        ("deadline_seconds", 300),
        ("run_bytes", 16 * 1024 * 1024),
        ("trace_entries", 100_000),
        ("session_ttl_seconds", 300),
    ] {
        for value in [
            "0".to_owned(),
            (cap + 1).to_string(),
            "1.0".into(),
            "1e0".into(),
            "\"1\"".into(),
            "-1".into(),
        ] {
            let json = format!("{{\"{key}\":{value}}}");
            assert!(serde_json::from_str::<ServiceLimits>(&json)
                .and_then(|v| v.validate().map_err(serde::de::Error::custom))
                .is_err());
        }
    }
    assert!(InstanceConfig::parse(
        &format!("bind = \"[::1]:8080\"\n{}", text()),
        Path::new("/instance/cdb.toml")
    )
    .is_ok());
}
#[test]
fn credential_strict() {
    let t = table();
    let bytes = serde_json::to_vec(&t).unwrap();
    assert!(CredentialTable::parse(&bytes).is_ok());
    let s = String::from_utf8(bytes).unwrap();
    for bad in [
        s.replacen('{', "{\"secret\":\"never\",", 1),
        s.replace("\"query\"", "\"root\""),
        s.replace("2099-01-01T00:00:00Z", "2099-01-01T00:00:00+01:00"),
        s.replace("true", "1.0"),
    ] {
        assert!(CredentialTable::parse(bad.as_bytes()).is_err());
    }
    let mut t = table();
    t.entries.push(table().entries.remove(0));
    assert!(t.auth_store(Duration::from_secs(300)).is_err());
    assert!(CredentialTable::parse(&vec![b' '; 1024 * 1024 + 1]).is_err());
}
#[cfg(unix)]
#[test]
fn private_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let path = root.join("secret");
    create_secret_file(&path, b"secret").unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(create_secret_file(&path, b"replacement").is_err());
    let reader = BoundedFileRead::new(32, true).unwrap();
    assert_eq!(reader.read(&path).unwrap(), b"secret");
    assert!(BoundedFileRead::new(2, true).unwrap().read(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(reader.read(&path).is_err());
    let link = root.join("link");
    symlink(&path, &link).unwrap();
    assert!(reader.read(&link).is_err());
    assert!(create_secret_file(&link, b"bad").is_err());
    let alias = root.join("alias");
    symlink(&root, &alias).unwrap();
    assert!(reader.read(&alias.join("secret")).is_err());
    assert!(create_secret_file(&alias.join("new"), b"bad").is_err());
    let table_path = root.join("credentials");
    table().write_new(&table_path).unwrap();
    assert!(CredentialTable::load(&table_path).is_ok());
    let config_path = root.join("cdb.toml");
    std::fs::write(&config_path, text()).unwrap();
    assert!(InstanceConfig::load(&config_path).is_ok());
}

#[test]
fn zero_work_is_a_rejecting_budget_not_an_invalid_configuration() {
    let config = InstanceConfig::parse(
        &(text() + "\n[limits]\nmax_work = 0\n"),
        Path::new("/instance/cdb.toml"),
    )
    .unwrap();
    assert_eq!(config.limits.max_work, 0);
    assert!(InstanceConfig::parse(
        &(text() + "\n[limits]\nmax_work = 0.0\n"),
        Path::new("/instance/cdb.toml")
    )
    .is_err());
}
