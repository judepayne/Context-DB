use cdb_backend_fluree::{
    official_bootstrap::{
        bootstrap_agreements, bootstrap_certified_agreements, bootstrap_commercial_loans,
        bootstrap_party_background,
    },
    runs::Operation as ControlOperation,
};
use cdb_core::{id::PrincipalId, CanonicalValue, Error, ErrorKind, Limits, Result};
use cdb_provider_pi::cancel::CancellationToken;
use cdb_service::{
    acquisition_inspection::AuthorizedAcquisition,
    auth,
    config::{AcquisitionAssertionPolicy, BoundedFileRead, InstanceConfig},
    http,
    ingest::{ingest, IngestMode, IngestWait, OntologyMode},
    source_target::SourceTarget,
    Service,
};
use std::{
    collections::BTreeMap,
    io::{IsTerminal, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{net::TcpListener, sync::watch};

const HELP: &str = "cdb <serve|init|provision|publish|query|run|replay|status|source> [--config /absolute/cdb.toml]
cdb chat [--config /absolute/cdb.toml] [--token-file /absolute/private-secret]
cdb ingest <start|inspect|artifact|resume|replay> --help
cdb ontology bootstrap --cache /absolute/pinned-fibo-cache --output /absolute/new-ledger-directory [--scope agreements|certified-agreements|commercial-loans|party-background]
init/provision: --principal ID --secret-file /absolute/new-secret [--admin (provision only)]
data commands: --token-file /absolute/private-secret --request-file /absolute/request.json
status may omit --request-file. No command-line bearer tokens are accepted.
For commands that use them, --config overrides CDB_CONFIG and --token-file overrides CDB_TOKEN_FILE; selected paths must be absolute.
Use cdb ingest --help for document ingestion. Top-level replay replays queries; ingest replay reprocesses saved extraction captures.";
const CHAT_HELP: &str = "cdb chat [--config /absolute/cdb.toml] [--token-file /absolute/private-secret]
Explicit flags override CDB_CONFIG and CDB_TOKEN_FILE independently. Selected paths must be absolute. Chat requires terminal input and output.";
const INGEST_HELP: &str = "cdb ingest <start|inspect|artifact|resume|replay>
  start     Extract from a file, HTTPS URL or non-recursive folder; optionally admit claims.
  inspect   Inspect retained ingestion outcomes.
  artifact  Retrieve an authorized retained ingestion artifact.
  resume    Continue eligible interrupted ingestion work.
  replay    Process a retained extraction capture without a new model call.
Use cdb ingest <subcommand> --help for arguments. Both --help and -h are supported.";
const INGEST_START_HELP: &str = "cdb ingest start --config /absolute/cdb.toml (--file PATH | --url HTTPS_URL | --folder PATH) ([--wait admitted|projected] | --extract-only) [--ontology-mode hard|soft] [--assertions accepted|evidence-only] [--captured-response FILE | --capture-manifest FILE | --save-capture-manifest FILE]
--ontology-mode defaults to hard. Soft admits exact source-backed provisional claims when no exact ontology mapping exists; the model never creates IRIs.
--assertions overrides the configured v2 assertion policy. evidence-only persists review evidence but writes no business claims.
--extract-only returns exact raw provider responses plus parse/validation status and performs no Semantic, Control, projection, or durable source-store writes. It cannot be combined with --wait.
--save-capture-manifest writes a create-new, mode-0600 manifest for a live response. --capture-manifest verifies request, model, staged bundle, ontology capture, ranges, source, and response bytes before replay. Raw --captured-response remains extract-only.
--config overrides CDB_CONFIG; the selected configuration path must be absolute.
Local source paths may be relative but must resolve beneath a configured allowed-local-roots entry. Folders are non-recursive; supported document types are .txt, .md, and configured .pdf.";
const INGEST_REPLAY_HELP: &str = "cdb ingest replay [--config /absolute/cdb.toml] [--token-file /absolute/private-secret] --capture ROOT --ontology-mode hard|soft --assertions accepted|evidence-only [--ephemeral|--extract-only]
--config and --token-file override CDB_CONFIG and CDB_TOKEN_FILE independently; selected paths must be absolute.
Reprocess a retained extraction capture without a fresh model call. --ephemeral (also --extract-only) suppresses all admissions and durable work/source changes. Historical captures do not bypass current authorization.";
fn invalid() -> Error {
    Error::invalid("invalid command arguments")
}
fn path(args: &mut BTreeMap<String, String>, key: &str) -> Result<PathBuf> {
    let path = PathBuf::from(args.remove(key).ok_or_else(invalid)?);
    if !path.is_absolute() {
        return Err(invalid());
    }
    Ok(path)
}
fn selected_path(
    args: &mut BTreeMap<String, String>,
    flag: &str,
    environment: &str,
) -> Result<PathBuf> {
    let selected = match args.remove(flag) {
        Some(value) => PathBuf::from(value),
        None => std::env::var_os(environment)
            .map(PathBuf::from)
            .ok_or_else(|| {
                Error::invalid(format!(
                    "missing {flag}; set {environment} to an absolute path"
                ))
            })?,
    };
    if selected.as_os_str().is_empty() || !selected.is_absolute() {
        return Err(Error::invalid(format!(
            "{flag}/{environment} must select an absolute path"
        )));
    }
    Ok(selected)
}
fn load_token(config: &InstanceConfig, token_path: &std::path::Path) -> Result<String> {
    let bytes = BoundedFileRead::new(config.limits.max_body_bytes, true)?.read(token_path)?;
    let token = std::str::from_utf8(&bytes)
        .map_err(|_| invalid())?
        .trim_end_matches(['\r', '\n']);
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(invalid());
    }
    Ok(token.to_owned())
}
fn output(bytes: &[u8]) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|_| stdout.write_all(b"\n"))
        .map_err(|_| Error::new(ErrorKind::Backend, "output failed"))
}
fn ontology_bootstrap(mut argv: impl Iterator<Item = String>) -> Result<()> {
    if argv.next().as_deref() != Some("bootstrap") {
        return Err(invalid());
    }
    let mut args = BTreeMap::new();
    while let Some(key) = argv.next() {
        if !["--cache", "--output", "--scope"].contains(&key.as_str()) {
            return Err(invalid());
        }
        let value = argv.next().ok_or_else(invalid)?;
        if args.insert(key, value).is_some() {
            return Err(invalid());
        }
    }
    let cache = path(&mut args, "--cache")?;
    let destination = path(&mut args, "--output")?;
    let scope = args
        .remove("--scope")
        .unwrap_or_else(|| "agreements".into());
    if ![
        "agreements",
        "certified-agreements",
        "commercial-loans",
        "party-background",
    ]
    .contains(&scope.as_str())
        || !args.is_empty()
    {
        return Err(invalid());
    }
    let receipt = std::thread::Builder::new()
        .name("cdb-ontology-bootstrap".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(async {
                    match scope.as_str() {
                        "agreements" => serde_json::to_vec_pretty(
                            &bootstrap_agreements(&cache, &destination)
                                .await
                                .map_err(|error| error.to_string())?,
                        ),
                        "certified-agreements" => {
                            let receipt = bootstrap_certified_agreements(&cache, &destination)
                                .await
                                .map_err(|error| error.to_string())?;
                            serde_json::to_vec_pretty(&serde_json::json!({
                                "schema": "ctxql-certified-ontology-bootstrap/v1",
                                "ledger": receipt.ledger,
                                "t": receipt.t,
                                "cid": receipt.cid,
                                "ontology_quad_count": receipt.ontology_quad_count,
                                "transaction_quad_count": receipt.transaction_quad_count,
                                "transaction_bytes": receipt.transaction_bytes,
                                "structural_node_count": receipt.structural_node_count,
                                "structural_mapping_root": receipt.structural_mapping_root.as_str()
                            }))
                        }
                        "commercial-loans" => serde_json::to_vec_pretty(
                            &bootstrap_commercial_loans(&cache, &destination)
                                .await
                                .map_err(|error| error.to_string())?,
                        ),
                        "party-background" => serde_json::to_vec_pretty(
                            &bootstrap_party_background(&cache, &destination)
                                .await
                                .map_err(|error| error.to_string())?,
                        ),
                        _ => unreachable!(),
                    }
                    .map_err(|error| error.to_string())
                })
        })
        .map_err(|error| Error::new(ErrorKind::Backend, error.to_string()))?
        .join()
        .map_err(|_| Error::new(ErrorKind::Backend, "ontology bootstrap worker panicked"))?
        .map_err(|error| Error::new(ErrorKind::Backend, error))?;
    output(&receipt)
}

async fn foreground_ingest(argv: impl Iterator<Item = String>) -> Result<()> {
    let values = argv.collect::<Vec<_>>();
    if values == ["--help"] || values == ["-h"] {
        println!("{INGEST_START_HELP}");
        return Ok(());
    }
    let mut argv = values.into_iter();
    let mut args = BTreeMap::new();
    let mut extract_only = false;
    while let Some(key) = argv.next() {
        if key == "--extract-only" {
            if extract_only {
                return Err(invalid());
            }
            extract_only = true;
            continue;
        }
        if ![
            "--config",
            "--file",
            "--url",
            "--folder",
            "--wait",
            "--ontology-mode",
            "--assertions",
            "--captured-response",
            "--capture-manifest",
            "--save-capture-manifest",
        ]
        .contains(&key.as_str())
        {
            return Err(invalid());
        }
        let value = argv.next().ok_or_else(invalid)?;
        if args.insert(key, value).is_some() {
            return Err(invalid());
        }
    }
    let config_path = selected_path(&mut args, "--config", "CDB_CONFIG")?;
    let ontology_mode = OntologyMode::parse(
        &args
            .remove("--ontology-mode")
            .unwrap_or_else(|| "hard".into()),
    )?;
    let wait = args.remove("--wait");
    let mode = if extract_only {
        if wait.is_some() {
            return Err(invalid());
        }
        IngestMode::ExtractOnly
    } else {
        IngestMode::Admit(IngestWait::parse(
            &wait.unwrap_or_else(|| "projected".into()),
        )?)
    };
    let targets = ["--file", "--url", "--folder"]
        .into_iter()
        .filter(|key| args.contains_key(*key))
        .collect::<Vec<_>>();
    if targets.len() != 1 {
        return Err(invalid());
    }
    let target = match targets[0] {
        "--file" => {
            SourceTarget::LocalFile(PathBuf::from(args.remove("--file").ok_or_else(invalid)?))
        }
        "--folder" => {
            SourceTarget::LocalFolder(PathBuf::from(args.remove("--folder").ok_or_else(invalid)?))
        }
        "--url" => SourceTarget::HttpsUrl(args.remove("--url").ok_or_else(invalid)?),
        _ => unreachable!(),
    };
    let assertions = args.remove("--assertions");
    let captured_response = args.remove("--captured-response");
    let capture_manifest = args.remove("--capture-manifest");
    let save_capture_manifest = args.remove("--save-capture-manifest");
    if !args.is_empty() {
        return Err(invalid());
    }
    let mut config = InstanceConfig::load(&config_path)?;
    if let Some(assertions) = assertions {
        config.acquisition.as_mut().ok_or_else(invalid)?.assertions =
            AcquisitionAssertionPolicy::parse(&assertions).map_err(|_| invalid())?;
    }
    let max_output = config.limits.run_bytes;
    let cancellation = CancellationToken::default();
    let operation = ingest(
        config,
        target,
        mode,
        ontology_mode,
        max_output,
        captured_response,
        capture_manifest,
        save_capture_manifest,
        cancellation.clone(),
    );
    tokio::pin!(operation);
    let report = tokio::select! {
        result = &mut operation => result?,
        _ = tokio::signal::ctrl_c() => {
            cancellation.cancel();
            let _ = (&mut operation).await;
            return Err(Error::new(ErrorKind::Deadline, "cancelled"));
        }
    };
    let bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| Error::new(ErrorKind::Backend, error.to_string()))?;
    if bytes.len() > max_output {
        return Err(Error::limit());
    }
    output(&bytes)
}

async fn ingest_command(mut argv: impl Iterator<Item = String>) -> Result<()> {
    let command = argv.next().unwrap_or_else(|| "--help".into());
    match command.as_str() {
        "--help" | "-h" if argv.next().is_none() => {
            println!("{INGEST_HELP}");
            Ok(())
        }
        "start" => foreground_ingest(argv).await,
        "replay" => ingest_replay_args(argv).await,
        "inspect" | "artifact" | "resume" => ingest_access(&command, argv).await,
        _ => Err(invalid()),
    }
}

async fn ingest_access(command: &str, argv: impl Iterator<Item = String>) -> Result<()> {
    let values = argv.collect::<Vec<_>>();
    if values == ["--help"] || values == ["-h"] {
        println!("cdb ingest {command} [--config /absolute/cdb.toml] [--token-file /absolute/private-secret] --request-file /absolute/request.json\nFlags override CDB_CONFIG and CDB_TOKEN_FILE independently; selected paths must be absolute.\nRequest schema: ctxql-acquisition-access/v1; op: {command}.");
        return Ok(());
    }
    let mut argv = values.into_iter();
    let mut args = BTreeMap::new();
    while let Some(key) = argv.next() {
        if !["--config", "--token-file", "--request-file"].contains(&key.as_str()) {
            return Err(invalid());
        }
        let value = argv.next().ok_or_else(invalid)?;
        if args.insert(key, value).is_some() {
            return Err(invalid());
        }
    }
    let config = InstanceConfig::load(&selected_path(&mut args, "--config", "CDB_CONFIG")?)?;
    let token_path = selected_path(&mut args, "--token-file", "CDB_TOKEN_FILE")?;
    let request_path = path(&mut args, "--request-file")?;
    if !args.is_empty() {
        return Err(invalid());
    }
    let token = load_token(&config, &token_path)?;
    let request = BoundedFileRead::new(config.limits.max_body_bytes, false)?.read(&request_path)?;
    let value = CanonicalValue::parse(&request, Limits::default())?;
    if value.field("schema")?.as_str()? != "ctxql-acquisition-access/v1"
        || value.field("op")?.as_str()? != command
    {
        return Err(invalid());
    }
    let access = AuthorizedAcquisition::open(config).await?;
    // Resume may cross an already-started native commit. Do not cancel it
    // by dropping the dispatch future; the owned session lease and final
    // authority fence provide the operation lifetime bound.
    let result = access.dispatch(&token, &request).await;
    let closed = access.shutdown().await;
    let response = result?;
    closed?;
    output(&response)
}

async fn ingest_replay_args(argv: impl Iterator<Item = String>) -> Result<()> {
    let values = argv.collect::<Vec<_>>();
    if values == ["--help"] || values == ["-h"] {
        println!("{INGEST_REPLAY_HELP}");
        return Ok(());
    }
    let mut argv = values.into_iter();
    let mut args = BTreeMap::new();
    let mut ephemeral = false;
    while let Some(key) = argv.next() {
        if matches!(key.as_str(), "--ephemeral" | "--extract-only") {
            if ephemeral {
                return Err(invalid());
            }
            ephemeral = true;
            continue;
        }
        if ![
            "--config",
            "--token-file",
            "--capture",
            "--ontology-mode",
            "--assertions",
        ]
        .contains(&key.as_str())
        {
            return Err(invalid());
        }
        let value = argv.next().ok_or_else(invalid)?;
        if args.insert(key, value).is_some() {
            return Err(invalid());
        }
    }
    let config = InstanceConfig::load(&selected_path(&mut args, "--config", "CDB_CONFIG")?)?;
    let token_path = selected_path(&mut args, "--token-file", "CDB_TOKEN_FILE")?;
    let capture = cdb_core::id::ContentHash::parse(args.remove("--capture").ok_or_else(invalid)?)?;
    let ontology_mode = OntologyMode::parse(&args.remove("--ontology-mode").ok_or_else(invalid)?)?;
    let assertions =
        AcquisitionAssertionPolicy::parse(&args.remove("--assertions").ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    if !args.is_empty() {
        return Err(invalid());
    }
    let token = load_token(&config, &token_path)?;
    let request = CanonicalValue::object([
        (
            "schema".into(),
            CanonicalValue::string("ctxql-acquisition-access/v1"),
        ),
        ("op".into(), CanonicalValue::string("replay")),
        (
            "capture_root".into(),
            CanonicalValue::string(capture.as_str()),
        ),
        (
            "ontology_mode".into(),
            CanonicalValue::string(ontology_mode.as_str()),
        ),
        (
            "assertions".into(),
            CanonicalValue::string(match assertions {
                AcquisitionAssertionPolicy::Accepted => "accepted",
                AcquisitionAssertionPolicy::EvidenceOnly => "evidence-only",
            }),
        ),
        ("ephemeral".into(), CanonicalValue::Bool(ephemeral)),
    ])?
    .canonical_bytes(Limits::default())?;
    let access = AuthorizedAcquisition::open_authenticated(
        config,
        &token,
        ControlOperation::Replay,
        auth::Operation::Replay,
    )
    .await?;
    let result = access.dispatch(&token, &request).await;
    let closed = access.shutdown().await;
    let response = result?;
    closed?;
    output(&response)
}

async fn chat_command(argv: impl Iterator<Item = String>) -> Result<()> {
    let values = argv.collect::<Vec<_>>();
    if values == ["--help"] || values == ["-h"] {
        println!("{CHAT_HELP}");
        return Ok(());
    }
    let mut argv = values.into_iter();
    let mut args = BTreeMap::new();
    while let Some(key) = argv.next() {
        if !["--config", "--token-file"].contains(&key.as_str()) {
            return Err(invalid());
        }
        let value = argv.next().ok_or_else(invalid)?;
        if args.insert(key, value).is_some() {
            return Err(invalid());
        }
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(Error::invalid("chat requires terminal input and output"));
    }
    let config_path = selected_path(&mut args, "--config", "CDB_CONFIG")?;
    let token_path = selected_path(&mut args, "--token-file", "CDB_TOKEN_FILE")?;
    if !args.is_empty() {
        return Err(invalid());
    }
    let config = InstanceConfig::load(&config_path)?;
    let token = load_token(&config, &token_path)?;
    cdb_service::chat::run_chat(config, token).await
}

async fn execute() -> Result<()> {
    let mut argv = std::env::args().skip(1);
    let command = argv.next().ok_or_else(invalid)?;
    if command == "--help" || command == "-h" {
        println!("{HELP}");
        return Ok(());
    }
    if command == "ontology" {
        return ontology_bootstrap(argv);
    }
    if command == "ingest" {
        return ingest_command(argv).await;
    }
    if command == "chat" {
        return chat_command(argv).await;
    }
    if ![
        "serve",
        "init",
        "provision",
        "publish",
        "query",
        "run",
        "replay",
        "status",
        "source",
    ]
    .contains(&command.as_str())
    {
        return Err(invalid());
    }
    let mut args = BTreeMap::new();
    while let Some(key) = argv.next() {
        if ![
            "--config",
            "--principal",
            "--secret-file",
            "--admin",
            "--token-file",
            "--request-file",
        ]
        .contains(&key.as_str())
        {
            return Err(invalid());
        }
        let value = if key == "--admin" {
            "true".to_owned()
        } else {
            argv.next().ok_or_else(invalid)?
        };
        if args.insert(key, value).is_some() {
            return Err(invalid());
        }
    }
    let config = InstanceConfig::load(&selected_path(&mut args, "--config", "CDB_CONFIG")?)?;
    if command == "init" || command == "provision" {
        let principal = PrincipalId::new(args.remove("--principal").ok_or_else(invalid)?)?;
        let secret = path(&mut args, "--secret-file")?;
        let admin = command == "provision" && args.remove("--admin").is_some();
        if !args.is_empty() {
            return Err(invalid());
        }
        return if command == "init" {
            Service::initialize(config, principal, secret).await
        } else {
            Service::provision(config, principal, secret, admin).await
        };
    }
    if command == "serve" {
        if !args.is_empty() {
            return Err(invalid());
        }
        let listener = TcpListener::bind(config.bind)
            .await
            .map_err(|_| Error::new(ErrorKind::Backend, "bind failed"))?;
        let service = Service::open(config).await?;
        let (stop, receiver) = watch::channel(false);
        let signal = tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = stop.send(true);
        });
        let result = http::serve(service.clone(), listener, receiver).await;
        signal.abort();
        let closed = service.shutdown().await;
        return result.and(closed);
    }
    let token_path = selected_path(&mut args, "--token-file", "CDB_TOKEN_FILE")?;
    let token = load_token(&config, &token_path)?;
    let request = if command == "status" && !args.contains_key("--request-file") {
        b"{\"schema\":\"ctxql-service/v1\",\"op\":\"status\"}".to_vec()
    } else {
        BoundedFileRead::new(config.limits.max_body_bytes, false)?
            .read(&path(&mut args, "--request-file")?)?
    };
    if !args.is_empty() {
        return Err(invalid());
    }
    // Strict exact-value parse only for adapter metadata; dispatch retains original bytes.
    let max = config.limits.max_body_bytes;
    let value = CanonicalValue::parse(
        &request,
        Limits::new(max, 256, max, max.saturating_mul(16), max)?,
    )?;
    let object = value.as_object()?;
    if object.get("op") != Some(&CanonicalValue::string(&command))
        || object.get("schema") != Some(&CanonicalValue::string("ctxql-service/v1"))
        || object.contains_key("token")
        || object.contains_key("authorization")
    {
        return Err(invalid());
    }
    let deadline = config.limits.deadline();
    let max_output = config.limits.run_bytes;
    let service = Service::open(config).await?;
    let cancellation = Arc::new(AtomicBool::new(false));
    let result = tokio::select! {
        result = tokio::time::timeout(deadline, service.dispatch(&token, &request, cancellation.clone())) => result.unwrap_or_else(|_| Err(Error::new(ErrorKind::Deadline, "deadline"))),
        _ = tokio::signal::ctrl_c() => Err(Error::new(ErrorKind::Deadline, "cancelled")),
    };
    cancellation.store(true, Ordering::Release);
    let closed = service.shutdown().await;
    let response = result?;
    closed?;
    if response.len() > max_output {
        return Err(Error::limit());
    }
    output(&response)
}
fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(16 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("cdb runtime");
    if let Err(error) = runtime.block_on(execute()) {
        if std::env::var_os("CDB_DEBUG_ERRORS").is_some() {
            eprintln!("{error:?}");
        }
        eprintln!("{}", error.public_json());
        std::process::exit(1);
    }
}
