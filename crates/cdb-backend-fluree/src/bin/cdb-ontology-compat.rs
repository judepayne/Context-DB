use cdb_backend_fluree::ontology_compatibility::{
    analyze_local_ontology, canonical_report_json, CompatibilityError, CompatibilityErrorKind,
    CompatibilityLimits, CompatibilityOptions,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

#[derive(Serialize)]
struct PublicError<'a> {
    error: &'a str,
}

fn main() {
    let code = match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(error) => {
            emit_error(&error);
            match error.kind {
                CompatibilityErrorKind::Invocation => 2,
                CompatibilityErrorKind::Limit => 4,
                CompatibilityErrorKind::Io | CompatibilityErrorKind::Serialization => 5,
            }
        }
    };
    std::process::exit(code);
}

fn run(args: Vec<String>) -> Result<i32, CompatibilityError> {
    if args.iter().any(|arg| arg == "--help") {
        println!("cdb-ontology-compat --root PATH --input PATH [--input PATH ...] [--entry IRI ...] [--import IRI=PATH ...] [--output PATH] [limit options]");
        return Ok(0);
    }
    let mut root = None;
    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    let mut imports = BTreeMap::new();
    let mut output = None;
    let mut limits = CompatibilityLimits::default();
    let mut index = 0;
    while index < args.len() {
        let option = &args[index];
        index += 1;
        let value = args.get(index).ok_or_else(invocation)?;
        index += 1;
        match option.as_str() {
            "--root" => set_once(&mut root, PathBuf::from(value))?,
            "--input" => inputs.push(PathBuf::from(value)),
            "--entry" => entries.push(value.clone()),
            "--import" => {
                let (iri, path) = value.split_once('=').ok_or_else(invocation)?;
                if iri.is_empty()
                    || path.is_empty()
                    || imports.insert(iri.into(), PathBuf::from(path)).is_some()
                {
                    return Err(invocation());
                }
            }
            "--output" => set_once(&mut output, PathBuf::from(value))?,
            "--max-files" => limits.max_files = number(value)?,
            "--max-bytes" => limits.max_bytes = number(value)?,
            "--max-triples" => limits.max_triples = number(value)?,
            "--max-import-depth" => limits.max_import_depth = number_allow_zero(value)?,
            "--max-list-length" => limits.max_list_length = number(value)?,
            "--max-expression-depth" => limits.max_expression_depth = number(value)?,
            "--max-diagnostics" => limits.max_diagnostics = number(value)?,
            "--max-report-bytes" => limits.max_report_bytes = number(value)?,
            _ => return Err(invocation()),
        }
    }
    let options = CompatibilityOptions {
        root: root.ok_or_else(invocation)?,
        inputs,
        entry_ontology_iris: entries,
        import_map: imports,
        limits,
    };
    let report = analyze_local_ontology(&options)?;
    let bytes = canonical_report_json(&report)?;
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|_| io_error("report_stdout_write_failed"))?;
    if let Some(path) = output {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| io_error("report_output_create_failed"))?;
        file.write_all(&bytes)
            .map_err(|_| io_error("report_output_write_failed"))?;
        file.sync_all()
            .map_err(|_| io_error("report_output_sync_failed"))?;
    }
    Ok(if report.is_compatible() { 0 } else { 3 })
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), CompatibilityError> {
    if slot.replace(value).is_some() {
        Err(invocation())
    } else {
        Ok(())
    }
}

fn number(value: &str) -> Result<usize, CompatibilityError> {
    let value = number_allow_zero(value)?;
    if value == 0 {
        Err(invocation())
    } else {
        Ok(value)
    }
}

fn number_allow_zero(value: &str) -> Result<usize, CompatibilityError> {
    value.parse().map_err(|_| invocation())
}

fn invocation() -> CompatibilityError {
    CompatibilityError {
        kind: CompatibilityErrorKind::Invocation,
        public_code: "invalid_invocation",
    }
}

fn io_error(code: &'static str) -> CompatibilityError {
    CompatibilityError {
        kind: CompatibilityErrorKind::Io,
        public_code: code,
    }
}

fn emit_error(error: &CompatibilityError) {
    let bytes = serde_json::to_vec(&PublicError {
        error: error.public_code,
    })
    .unwrap_or_else(|_| b"{\"error\":\"report_serialization_failed\"}".to_vec());
    let _ = std::io::stderr().write_all(&bytes);
    let _ = std::io::stderr().write_all(b"\n");
}
