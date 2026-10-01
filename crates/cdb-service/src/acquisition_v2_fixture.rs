//! Hermetic fresh-store harness for acquisition-v2 integration tests.
//!
//! This module provisions storage only. Foreground orchestration remains on the
//! production service path; tests may configure the fake Pi response, but may
//! not bypass transport, validation, review admission, or business admission.

use crate::{acquisition::load_current_catalog, config::InstanceConfig, Service};
use cdb_backend_fluree::official_bootstrap::{
    bootstrap_acquisition_v2_fixture_with_denied_claims, AcquisitionV2BootstrapReceipt,
    ACQUISITION_V2_FIXTURE_ACTION, ACQUISITION_V2_FIXTURE_CLAIMS_GRAPH,
    ACQUISITION_V2_FIXTURE_LEDGER, ACQUISITION_V2_FIXTURE_PRINCIPAL,
    ACQUISITION_V2_FIXTURE_REVIEW_GRAPH,
};
use cdb_backend_fluree::CertifiedOntologyCatalog;
use cdb_core::{id::PrincipalId, ontology_catalog::OntologyCatalogIdentity};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

pub type FixtureResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct AcquisitionV2Fixture {
    root: PathBuf,
    _temporary_root: Option<TempDir>,
    config_path: PathBuf,
    response_path: PathBuf,
    invocation_path: PathBuf,
    bootstrap: AcquisitionV2BootstrapReceipt,
    catalog: OntologyCatalogIdentity,
}

fn fixture_error(message: &'static str) -> Box<dyn std::error::Error + Send + Sync> {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message).into()
}

fn fixture_text(value: &serde_json::Value, key: &str) -> FixtureResult<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| fixture_error("invalid JSON proposal fixture"))
}

fn render_fixture_choice(
    output: &mut String,
    label: &str,
    value: &serde_json::Value,
) -> FixtureResult<()> {
    let suggestions = value
        .get("suggestions")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| fixture_error("invalid JSON proposal fixture choice"))?;
    for suggestion in suggestions {
        output.push_str(&format!(
            "{label}: {}\n{label} note: {}\n",
            fixture_text(suggestion, "text")?,
            fixture_text(suggestion, "note")?
        ));
    }
    let selected = value
        .get("selected")
        .ok_or_else(|| fixture_error("invalid JSON proposal fixture choice"))?;
    output.push_str(&format!(
        "{label} selected: {}\n",
        selected
            .as_u64()
            .map_or_else(|| "none".to_owned(), |value| value.to_string())
    ));
    Ok(())
}

fn render_fixture_evidence(output: &mut String, evidence: &serde_json::Value) -> FixtureResult<()> {
    for item in evidence
        .as_array()
        .ok_or_else(|| fixture_error("invalid JSON proposal fixture evidence"))?
    {
        output.push_str(&format!(
            "EVIDENCE:\nRange: {}\nOccurrence: {}\nQuote: {}\n",
            fixture_text(item, "range")?,
            item.get("occurrence")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| fixture_error("invalid JSON proposal fixture evidence"))?,
            fixture_text(item, "quote")?
        ));
    }
    Ok(())
}

fn render_fixture_metadata(
    output: &mut String,
    value: &serde_json::Value,
    qualifiers: bool,
) -> FixtureResult<()> {
    output.push_str(&format!(
        "CLAIM_METADATA:\nSource mode: {}\nFit: {}\nFit note: {}\n",
        fixture_text(value, "source_mode")?,
        fixture_text(value, "fit")?,
        fixture_text(value, "fit_note")?
    ));
    if qualifiers {
        for qualifier in value
            .get("qualifiers")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            output.push_str(&format!(
                "Qualifier: {}\n",
                qualifier
                    .as_str()
                    .ok_or_else(|| fixture_error("invalid JSON proposal fixture qualifier"))?
            ));
        }
    }
    Ok(())
}

fn render_fixture_reference(value: &serde_json::Value, object: bool) -> FixtureResult<String> {
    let kind = fixture_text(value, "kind")?;
    match kind.as_str() {
        "local" => Ok(format!("local {}", fixture_text(value, "id")?)),
        "document" => Ok(format!("document {}", fixture_text(value, "handle")?)),
        "known" => Ok(format!("known {}", fixture_text(value, "iri")?)),
        "unresolved" if object => Ok(format!("unresolved {}", fixture_text(value, "text")?)),
        _ => Err(fixture_error("invalid JSON proposal fixture reference")),
    }
}

fn proposal_json_fixture_to_text(response: &str) -> FixtureResult<String> {
    let value: serde_json::Value = serde_json::from_str(response)?;
    if value.get("no_claims").and_then(serde_json::Value::as_bool) == Some(true) {
        return Ok("NO_CLAIMS".into());
    }
    let mut output = String::new();
    for entity in value
        .get("entities")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| fixture_error("invalid JSON proposal fixture entities"))?
    {
        output.push_str(&format!(
            "ENTITY:\nId: {}\nName: {}\nKnown entity: {}\n",
            fixture_text(entity, "id")?,
            fixture_text(entity, "name")?,
            entity
                .get("known_entity")
                .and_then(serde_json::Value::as_str)
                .map_or_else(|| "none".to_owned(), |iri| format!("iri {iri}"))
        ));
        render_fixture_evidence(&mut output, &entity["evidence"])?;
        output.push_str("---\n");
        for alias in entity
            .get("aliases")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            output.push_str(&format!(
                "ALIAS:\nEntity: {}\nName: {}\n",
                fixture_text(entity, "id")?,
                fixture_text(alias, "name")?
            ));
            render_fixture_evidence(&mut output, &alias["evidence"])?;
            output.push_str("---\n");
        }
        for class in entity
            .get("classes")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            output.push_str(&format!(
                "CLAIM:\nKind: classification\nSubject: local {}\n",
                fixture_text(entity, "id")?
            ));
            render_fixture_choice(&mut output, "Term", &class["term"])?;
            render_fixture_metadata(&mut output, class, false)?;
            render_fixture_evidence(&mut output, &class["evidence"])?;
            output.push_str("---\n");
        }
    }
    for attribute in value
        .get("attributes")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        output.push_str(&format!(
            "CLAIM:\nKind: attribute\nSubject: {}\n",
            render_fixture_reference(&attribute["subject"], false)?
        ));
        render_fixture_choice(&mut output, "Predicate", &attribute["predicate"])?;
        output.push_str(&format!(
            "Value: {}\n",
            fixture_text(&attribute["value"], "lexical")?
        ));
        render_fixture_choice(&mut output, "Datatype", &attribute["value"]["datatype"])?;
        render_fixture_metadata(&mut output, attribute, true)?;
        render_fixture_evidence(&mut output, &attribute["evidence"])?;
        output.push_str("---\n");
    }
    for relation in value
        .get("relations")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        output.push_str(&format!(
            "CLAIM:\nKind: relation\nSubject: {}\n",
            render_fixture_reference(&relation["subject"], false)?
        ));
        render_fixture_choice(&mut output, "Predicate", &relation["predicate"])?;
        output.push_str(&format!(
            "Object: {}\n",
            render_fixture_reference(&relation["object"], true)?
        ));
        render_fixture_metadata(&mut output, relation, true)?;
        render_fixture_evidence(&mut output, &relation["evidence"])?;
        output.push_str("---\n");
    }
    output.pop();
    Ok(output)
}

/// Pinned external dependencies used by a retained real-provider fixture.
pub struct PersistentAcquisitionV2Config<'a> {
    pub root: &'a Path,
    pub pi_command: &'a Path,
    pub ontology_ledger_path: &'a Path,
    pub allowed_source_root: &'a Path,
    /// Optional `(command, version, executable hash, arguments, normalization)`.
    pub pdf_converter: Option<(&'a Path, &'a str, &'a str, &'a [String], &'a str)>,
}

impl AcquisitionV2Fixture {
    /// Create independent Semantic, Control, projection, source, credential and
    /// fake-provider state. No file is copied from a historical Control store.
    pub async fn create() -> FixtureResult<Self> {
        let temporary_root = match std::env::var_os("CDB_A2_EVIDENCE_DIR") {
            Some(directory) => {
                let directory = PathBuf::from(directory);
                if !directory.is_absolute() || !directory.is_dir() {
                    return Err(
                        "fixture evidence directory must be an existing absolute directory".into(),
                    );
                }
                tempfile::Builder::new()
                    .prefix("acquisition-v2-")
                    .tempdir_in(directory)?
            }
            None => tempfile::tempdir()?,
        };
        let root = temporary_root.path().canonicalize()?;
        let pi = root.join("fake-pi.py");
        let response_path = root.join("pi-response.json");
        let invocation_path = root.join("pi-invocations");
        fs::write(&response_path, "NO_CLAIMS")?;
        fs::write(&invocation_path, b"0\n")?;
        write_fake_pi(&pi)?;
        Self::initialize_at(
            root,
            Some(temporary_root),
            pi,
            response_path,
            invocation_path,
            None,
            None,
            None,
            &[],
        )
        .await
    }

    /// Create a fresh fixture whose Semantic policy graph denies the supplied
    /// claim identities to the fixture principal for view operations.
    pub async fn create_with_semantic_denials(denied_claims: &[String]) -> FixtureResult<Self> {
        let temporary_root = tempfile::tempdir()?;
        let root = temporary_root.path().canonicalize()?;
        let pi = root.join("fake-pi.py");
        let response_path = root.join("pi-response.json");
        let invocation_path = root.join("pi-invocations");
        fs::write(&response_path, "NO_CLAIMS")?;
        fs::write(&invocation_path, b"0\n")?;
        write_fake_pi(&pi)?;
        Self::initialize_at(
            root,
            Some(temporary_root),
            pi,
            response_path,
            invocation_path,
            None,
            None,
            None,
            denied_claims,
        )
        .await
    }

    /// Create a fresh retained fixture for real-provider acceptance evidence.
    /// The root must not already exist, preventing accidental reuse of stores.
    pub async fn create_persistent(
        options: PersistentAcquisitionV2Config<'_>,
    ) -> FixtureResult<Self> {
        if options.root.exists() {
            return Err("persistent fixture root already exists".into());
        }
        if !options.root.is_absolute()
            || !options.pi_command.is_absolute()
            || !options.ontology_ledger_path.is_absolute()
            || !options.allowed_source_root.is_absolute()
        {
            return Err("persistent fixture paths must be absolute".into());
        }
        fs::create_dir_all(options.root)?;
        let root = options.root.canonicalize()?;
        Self::initialize_at(
            root.clone(),
            None,
            options.pi_command.to_path_buf(),
            root.join("real-provider-response-unused.json"),
            root.join("real-provider-invocations-unavailable"),
            Some(options.ontology_ledger_path),
            Some(options.allowed_source_root),
            options.pdf_converter,
            &[],
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn initialize_at(
        root: PathBuf,
        temporary_root: Option<TempDir>,
        pi: PathBuf,
        response_path: PathBuf,
        invocation_path: PathBuf,
        ontology_ledger_path: Option<&Path>,
        allowed_source_root: Option<&Path>,
        pdf_converter: Option<(&Path, &str, &str, &[String], &str)>,
        denied_claims: &[String],
    ) -> FixtureResult<Self> {
        let semantic_path = root.join("semantic");
        let bootstrap =
            bootstrap_acquisition_v2_fixture_with_denied_claims(&semantic_path, denied_claims)
                .await?;
        fs::create_dir(root.join("documents"))?;
        let pi_bundle = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../assets/pi")
            .canonicalize()?;
        let config_path = root.join("cdb.toml");
        let default_source_root = root.join("documents");
        let source_root = allowed_source_root.unwrap_or(&default_source_root);
        let pending_root = cdb_core::id::ContentHash::of_bytes(b"pending");
        fs::write(
            &config_path,
            config_text(
                &pi,
                &pi_bundle,
                pending_root.as_str(),
                ontology_ledger_path,
                source_root,
                pdf_converter,
            ),
        )?;
        let provisional = InstanceConfig::load(&config_path)?;
        let catalog = load_current_catalog(&provisional).await?;
        fs::write(
            &config_path,
            config_text(
                &pi,
                &pi_bundle,
                catalog.identity().catalog_root().as_str(),
                ontology_ledger_path,
                source_root,
                pdf_converter,
            ),
        )?;
        let config = InstanceConfig::load(&config_path)?;
        Service::initialize(
            config,
            PrincipalId::new(ACQUISITION_V2_FIXTURE_PRINCIPAL)?,
            root.join("owner.secret"),
        )
        .await?;
        Ok(Self {
            root,
            _temporary_root: temporary_root,
            config_path,
            response_path,
            invocation_path,
            bootstrap,
            catalog: catalog.identity().clone(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }
    pub fn config(&self) -> FixtureResult<InstanceConfig> {
        Ok(InstanceConfig::load(&self.config_path)?)
    }
    pub fn bootstrap_receipt(&self) -> &AcquisitionV2BootstrapReceipt {
        &self.bootstrap
    }
    pub fn catalog_identity(&self) -> &OntologyCatalogIdentity {
        &self.catalog
    }

    pub async fn reload_catalog(&self) -> FixtureResult<CertifiedOntologyCatalog> {
        Ok(load_current_catalog(&self.config()?).await?)
    }

    /// Supply the advisory model envelope returned over the real Pi RPC
    /// subprocess boundary. `{{WINDOW_ID}}`, `{{PASSAGE_NAMESPACE}}`,
    /// `{{WINDOW_RANGE}}`, and one-based `{{LINE_RANGE_N}}` strings are replaced
    /// from the actual host-issued v2 prompt by the fake child process. This is
    /// provider injection only, not host-result injection.
    pub fn set_pi_response(&self, response: &str) -> FixtureResult<()> {
        // Older deterministic service fixtures are stored as v2 JSON values.
        // Convert them before the fake provider emits bytes so live requests
        // exercise the explicitly bound text protocol; production never falls
        // back from text parsing to JSON parsing.
        let response = if response.trim_start().starts_with('{') {
            proposal_json_fixture_to_text(response)?
        } else {
            response.to_owned()
        };
        fs::write(&self.response_path, response)?;
        Ok(())
    }

    /// Configure the fake model to exercise both identity boundaries: the
    /// approved agreement is reusable from grounded identifying evidence, while
    /// the readable but unapproved party IRI must remain only a proposal.
    pub fn set_identity_pi_response(
        &self,
        approved_agreement: &str,
        readable_unapproved_party: &str,
    ) -> FixtureResult<()> {
        let entity = |id: &str, name: &str, known: Option<&str>, line: usize, quote: &str| {
            format!(
                "ENTITY:\nId: {id}\nName: {name}\nKnown entity: {}\nEVIDENCE:\nRange: {{{{LINE_RANGE_{line}}}}}\nOccurrence: 0\nQuote: {quote}\n---",
                known.map_or_else(|| "none".to_owned(), |iri| format!("iri {iri}"))
            )
        };
        let class = |subject: &str, iri: &str, line: usize, quote: &str| {
            format!(
                "CLAIM:\nKind: classification\nSubject: local {subject}\nTerm: {iri}\nTerm note:\nTerm selected: 0\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\nEVIDENCE:\nRange: {{{{LINE_RANGE_{line}}}}}\nOccurrence: 0\nQuote: {quote}\n---"
            )
        };
        let relation = |object: &str, line: usize, quote: &str| {
            format!(
                "CLAIM:\nKind: relation\nSubject: local e1\nPredicate: urn:ctxql:a2:hasBorrower\nPredicate note:\nPredicate selected: 0\nObject: local {object}\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\nEVIDENCE:\nRange: {{{{LINE_RANGE_{line}}}}}\nOccurrence: 0\nQuote: {quote}\n---"
            )
        };
        let response = [
            entity(
                "e1",
                "Orion",
                Some(approved_agreement),
                1,
                &format!("Orion identifies its borrower as {readable_unapproved_party}."),
            ),
            entity(
                "e2",
                "Acme Ltd",
                Some(readable_unapproved_party),
                1,
                "Acme Ltd as urn:ctxql:a2:Borrower",
            ),
            entity("e3", "New Party LLC", None, 2, "New Party LLC"),
            class(
                "e1",
                "urn:ctxql:a2:CreditAgreement",
                1,
                "Orion identifies as urn:ctxql:a2:CreditAgreement",
            ),
            class("e1", "urn:ctxql:a2:WrittenContract", 1, "Orion"),
            class(
                "e3",
                "urn:ctxql:a2:Borrower",
                2,
                "New Party LLC is also a borrower.",
            ),
            "CLAIM:\nKind: attribute\nSubject: local e1\nPredicate: urn:ctxql:a2:executedOn\nPredicate note:\nPredicate selected: 0\nValue: 2022-12-06\nDatatype: http://www.w3.org/2001/XMLSchema#date\nDatatype note:\nDatatype selected: 0\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\nEVIDENCE:\nRange: {{LINE_RANGE_3}}\nOccurrence: 0\nQuote: Orion was executed on 2022-12-06.\n---".to_owned(),
            relation(
                "e2",
                1,
                "approved borrower Acme Ltd as urn:ctxql:a2:Borrower",
            ),
            relation("e3", 2, "New Party LLC is also a borrower."),
        ]
        .join("\n");
        self.set_pi_response(&response)
    }

    pub fn graph_query_invocations(&self) -> u64 {
        crate::graph_query::execution_count_for_fixture()
    }

    pub fn pi_invocations(&self) -> FixtureResult<u64> {
        Ok(fs::read_to_string(&self.invocation_path)?.trim().parse()?)
    }

    pub async fn set_graph_query_access(
        &self,
        service: &Service,
        allowed: bool,
    ) -> FixtureResult<()> {
        service.set_graph_query_access_for_fixture(allowed).await?;
        Ok(())
    }

    pub async fn revoke_source_access(&self, service: &Service) -> FixtureResult<()> {
        service.revoke_source_access_for_fixture().await?;
        Ok(())
    }

    pub fn write_document(&self, name: &str, bytes: &[u8]) -> FixtureResult<PathBuf> {
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name == "."
            || name == ".."
        {
            return Err("fixture document name must be one path component".into());
        }
        let path = self.root.join("documents").join(name);
        fs::write(&path, bytes)?;
        Ok(path.canonicalize()?)
    }
}

fn config_text(
    pi: &Path,
    pi_bundle: &Path,
    catalog_root: &str,
    ontology_ledger_path: Option<&Path>,
    allowed_source_root: &Path,
    pdf_converter: Option<(&Path, &str, &str, &[String], &str)>,
) -> String {
    let backend = cdb_core::recording_v5::BACKEND_ID;
    let profile = cdb_core::recording_v5::CURRENT_ACQUISITION_PROFILE_ID;
    let ontology = ontology_ledger_path
        .map(|path| format!("ontology-ledger-path = {:?}\n", path.display().to_string()))
        .unwrap_or_else(|| "ontology-briefing = { schema = \"ctxql-ontology-briefing-seeds/v1\", topic = \"synthetic-a2\", seeds = [{ iri = \"urn:ctxql:a2:CreditAgreement\", kind = \"class\", priority = 1 }, { iri = \"urn:ctxql:a2:Borrower\", kind = \"class\", priority = 2 }, { iri = \"urn:ctxql:a2:hasBorrower\", kind = \"object_property\", priority = 3 }, { iri = \"urn:ctxql:a2:executedOn\", kind = \"datatype_property\", priority = 4 }] }\n".to_owned());
    let converter = pdf_converter
        .map(|(command, version, hash, arguments, normalization)| {
            format!(
                "[acquisition.converters.pdf]\ncommand = {:?}\nversion = {:?}\nexecutable-hash = {:?}\narguments = {}\nnormalization = {:?}\n",
                command.display().to_string(),
                version,
                hash,
                serde_json::to_string(arguments).expect("converter arguments encode"),
                normalization,
            )
        })
        .unwrap_or_default();
    format!(
        r#"schema = "ctxql-instance/v4"
projection = "projection"
credential-file = "credentials.json"
source-root = "sources"
[semantic]
path = "semantic"
ledger = "{ledger}"
backend = "{backend}"
authority = "urn:ctxql:a2:semantic-authority"
graph = "urn:ctxql:a2:semantic-graph"
[control]
path = "control"
ledger = "control:main"
backend = "urn:ctxql:a2:control-backend"
authority = "urn:ctxql:a2:control-authority"
graph = "urn:ctxql:a2:control-graph"
[limits]
deadline_seconds = 30
session_ttl_seconds = 300
[acquisition]
access-mode = "direct"
protocol = "ontology-v2"
assertions = "accepted"
review-graph = "{review}"
claims-graph = "{claims}"
principal = "{principal}"
action = "{action}"
pi-command = "{pi}"
pi-bundle = "{bundle}"
extractor_model = "openrouter/deepseek/deepseek-v4.1-flash"
thinking = "high"
batch-size = 2
max-source-bytes = 33554432
max-document-bytes = 33554432
max-folder-entries = 100
provider-timeout-seconds = 300
projection-timeout-seconds = 10
control-journal-bytes = 1048576
ontology-profile = "{profile}"
ontology-catalog-root = "{catalog_root}"
{ontology}allowed-local-roots = ["{source_root}"]
[acquisition.window]
mode = "off"
target-bytes = 4096
max-bytes = 65536
overlap-bytes = 256
{converter}"#,
        ledger = ACQUISITION_V2_FIXTURE_LEDGER,
        review = ACQUISITION_V2_FIXTURE_REVIEW_GRAPH,
        claims = ACQUISITION_V2_FIXTURE_CLAIMS_GRAPH,
        principal = ACQUISITION_V2_FIXTURE_PRINCIPAL,
        action = ACQUISITION_V2_FIXTURE_ACTION,
        pi = pi.display(),
        bundle = pi_bundle.display(),
        source_root = allowed_source_root.display(),
        ontology = ontology,
        converter = converter,
    )
}

fn write_fake_pi(path: &Path) -> FixtureResult<()> {
    fs::write(
        path,
        r#"#!/usr/bin/env python3
import json, os, pathlib, socket, sys
root = pathlib.Path(__file__).resolve().parent

call_sequence = 0
def host_call(capability, request):
    global call_sequence
    call_sequence += 1
    envelope = {
        "token": os.environ["CTXQL_ONTOLOGY_TOKEN"],
        "kind": "call",
        "call_id": "fixture-graph-" + str(call_sequence),
        "capability": capability,
        "request": request,
    }
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(10)
    client.connect(os.environ["CTXQL_ONTOLOGY_SOCKET"])
    client.sendall(json.dumps(envelope, separators=(",", ":")).encode() + b"\n")
    chunks = []
    while True:
        chunk = client.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    client.close()
    result = json.loads(b"".join(chunks))
    if result.get("ok") is not True:
        raise RuntimeError("graph host denied: " + str(result.get("error")))
    return result["response"]

def substitute(value, replacements):
    if isinstance(value, str):
        for key, replacement in replacements.items():
            value = value.replace("{{" + key + "}}", replacement)
        return value
    if isinstance(value, list):
        return [substitute(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item, replacements) for key, item in value.items()}
    return value

for line in sys.stdin:
    request = json.loads(line)
    ident = request.get("id", "")
    method = request.get("method", request.get("type", ""))
    if method == "new_session":
        print(json.dumps({"type":"response","id":ident,"success":True,"data":{}}), flush=True)
    elif method == "get_session_stats":
        print(json.dumps({"type":"response","id":ident,"success":True,"data":{"input_tokens":1,"output_tokens":1,"cost_microusd":0}}), flush=True)
    elif method == "prompt":
        if not os.environ.get("OPENROUTER_API_KEY"):
            sys.exit(17)
        prompt = json.loads(request["message"])
        ranges = prompt["ranges"]
        window = next(item for item in ranges if item["kind"] == "window")
        lines = [item for item in ranges if item["kind"] == "line"]
        replacements = {
            "WINDOW_ID": prompt["window_id"],
            "PASSAGE_NAMESPACE": prompt["passage_namespace"],
            "WINDOW_RANGE": window["range"],
        }
        for index, item in enumerate(lines, 1):
            replacements["LINE_RANGE_" + str(index)] = item["range"]
        response = substitute((root / "pi-response.json").read_text(), replacements)
        count_file = root / "pi-invocations"
        count_file.write_text(str(int(count_file.read_text().strip()) + 1) + "\n")
        print(json.dumps({"type":"tool_execution_start","toolCallId":"skill-1","toolName":"ctxql_skill","args":{"name":"read-loan-agreement-v2"}}), flush=True)
        print(json.dumps({"type":"tool_execution_end","toolCallId":"skill-1","toolName":"ctxql_skill","isError":False}), flush=True)
        if os.environ.get("CTXQL_GRAPH_WORKSPACE_ENABLED"):
            for skill in ["ctxql-ontology", "ctxql-query", "graph-workspace"]:
                call_id = "skill-" + skill
                print(json.dumps({"type":"tool_execution_start","toolCallId":call_id,"toolName":"ctxql_skill","args":{"name":skill}}), flush=True)
                print(json.dumps({"type":"tool_execution_end","toolCallId":call_id,"toolName":"ctxql_skill","isError":False}), flush=True)
            query_path = root / "graph-query.json"
            query_text = query_path.read_text() if query_path.exists() else json.dumps({"about":[{"from":["urn:ctxql:fixture:missing"],"match":"exact"}],"bounds":{"max_depth":1,"seed_limit":1,"fanout_limit":4,"max_claims":8,"path_limit":4}})
            query = host_call("graph_query", {"query": query_text})
            if query_path.exists() and query.get("claim_count", 0) == 0:
                raise RuntimeError("fixture expected nonempty graph context")
            if query.get("status") != "graph" or query.get("complete") is not True or not query.get("overview"):
                raise RuntimeError("fixture graph query did not return a complete overview")
            host_call("graph_playground", {"operation":"import","handle":query["handle"]})
            mutation = {
                "operation":"apply", "expected_revision":1,
                "idempotency_key":"fixture-reference-v1",
                "edits":[
                    {"op":"add_node","temp_id":"new-party","local_id":"e2","label":"Acme Ltd","evidence":[window["range"]]},
                    {"op":"add_node","temp_id":"second-party","local_id":"e3","label":"New Party LLC","evidence":[window["range"]]},
                    {"op":"add_reference","temp_id":"collective","label":"Original Borrowers","scope":"document","definition_evidence":[window["range"]],"referent_shape":"set_of_parties","target_text":"Schedule 1","members":[{"kind":"temp","id":"new-party"},{"kind":"temp","id":"second-party"}],"membership_evidence":[window["range"]],"status":"resolved"}
                ]
            }
            stale = dict(mutation)
            stale["expected_revision"] = 0
            stale["idempotency_key"] = "fixture-stale-revision-v1"
            conflict = host_call("graph_playground", stale)
            if conflict != {"schema":"ctxql-graph-tool-error/v1","status":"error","code":"preparation_failed"}:
                raise RuntimeError("revision conflict did not return the exact public tool error")
            first = host_call("graph_playground", mutation)
            retry = host_call("graph_playground", mutation)
            if first != retry:
                raise RuntimeError("idempotent retry changed result")
            host_call("graph_playground", {"operation":"view","view":"overview"})
            host_call("graph_playground", {"operation":"release_graph","handle":query["handle"]})
        print(json.dumps({"type":"response","id":ident,"success":True,"data":{}}), flush=True)
        print(json.dumps({"type":"agent_end","model":"deepseek/deepseek-v4.1-flash","messages":[{"role":"assistant","text":response}]}), flush=True)
"#,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}
