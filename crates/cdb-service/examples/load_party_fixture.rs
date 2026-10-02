//! Compatibility helper for loading the pinned party-background fixture.
//! New scripted datasets should use the generic `cdb import` command; this
//! example retains the historical fixture identity until demo callers migrate.
use cdb_backend_fluree::runs::Operation as ControlOperation;
use cdb_core::{Error, ErrorKind, Limits, Result};
use cdb_service::{
    acquisition_inspection::AuthorizedAcquisition,
    auth,
    config::{BoundedFileRead, InstanceConfig},
};
use std::{collections::BTreeMap, io::Write, path::PathBuf};

const HELP: &str = "load_party_fixture --config /absolute/cdb.toml --token-file /absolute/private-secret --request-file /absolute/party-seed.json\n\nLoads only the pinned party-background fixture through authenticated ordinary admission.\nBuild with: cargo build --locked -p cdb-service --example load_party_fixture";

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

fn output(bytes: &[u8]) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|_| stdout.write_all(b"\n"))
        .map_err(|_| Error::new(ErrorKind::Backend, "output failed"))
}

async fn execute() -> Result<()> {
    let values = std::env::args().skip(1).collect::<Vec<_>>();
    if values == ["--help"] || values == ["-h"] {
        println!("{HELP}");
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

    let config = InstanceConfig::load(&path(&mut args, "--config")?)?;
    let token_path = path(&mut args, "--token-file")?;
    let request_path = path(&mut args, "--request-file")?;
    if !args.is_empty() {
        return Err(invalid());
    }

    let token_bytes =
        BoundedFileRead::new(config.limits.max_body_bytes, true)?.read(&token_path)?;
    let token = std::str::from_utf8(&token_bytes)
        .map_err(|_| invalid())?
        .trim_end_matches(['\r', '\n']);
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(invalid());
    }
    let request = BoundedFileRead::new(config.limits.max_body_bytes, false)?.read(&request_path)?;
    let access = AuthorizedAcquisition::open_authenticated(
        config,
        token,
        ControlOperation::Admin,
        auth::Operation::Admin,
    )
    .await?;
    let result = access.seed_party_background(token, &request).await;
    let closed = access.shutdown().await;
    let result = result?;
    closed?;
    output(&result.canonical_bytes(Limits::default())?)
}

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(16 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("ctxql fixture loader runtime");
    if let Err(error) = runtime.block_on(execute()) {
        if std::env::var_os("CDB_DEBUG_ERRORS").is_some() {
            eprintln!("{error:?}");
        }
        eprintln!("{}", error.public_json());
        std::process::exit(1);
    }
}
