use cdb_acquisition::candidates::CandidateLimits;
use cdb_provider_pi::advisory::into_advisory;
use cdb_provider_pi::agent_bundle::hash_agent_bundle;
use cdb_provider_pi::cancel::CancellationToken;
use cdb_provider_pi::ontology_bridge::{OntologyBridgeConfig, OntologyToolError, OntologyToolHost};
use cdb_provider_pi::parser::ParseLimits;
use cdb_provider_pi::provider::PiProvider;
use cdb_provider_pi::transport::{
    ExtractionProtocol, PiTransport, TransportConfig, TransportLimits,
};
use std::{
    env,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

struct PinnedLookup {
    calls: Arc<AtomicUsize>,
}
impl OntologyToolHost for PinnedLookup {
    fn lookup(&self, request: &serde_json::Value) -> Result<serde_json::Value, OntologyToolError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(serde_json::json!({
            "schema": "ctxql-ontology-tool-response/v1",
            "capture": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "catalog_root": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "request": request,
            "terms": [
                "urn:relation:hasBorrower",
                "urn:relation:hasLender",
                "urn:ctxql:acquisition:v1:BusinessRelationshipRelationType",
                "urn:ctxql:acquisition:v1:BusinessRelationshipClaimType",
                "urn:ctxql:acquisition:v1:TypeAssertionRelationType",
                "urn:ctxql:acquisition:v1:TypeAssertionClaimType",
                "urn:type:loanAgreement",
                "urn:type:legalEntity",
                "http://www.w3.org/2000/01/rdf-schema#Class",
                "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
            ]
        }))
    }
}

#[test]
#[ignore = "requires configured OpenRouter access and incurs provider cost"]
fn real_pinned_model_produces_a_closed_host_grounded_bundle() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/pi");
    let pi_command = PathBuf::from(
        env::var_os("CDB_PAID_PROVIDER_PI_COMMAND")
            .expect("CDB_PAID_PROVIDER_PI_COMMAND must name the Pi executable"),
    );
    assert!(pi_command.is_absolute());
    assert!(pi_command.is_file());
    let bundle = hash_agent_bundle(&root).unwrap();
    let system_prompt = bundle.system_prompt().unwrap();
    let mut envs = Vec::new();
    for key in ["HOME", "PATH", "OPENROUTER_API_KEY"] {
        envs.push((
            key.to_owned(),
            env::var(key).expect("required R3 environment"),
        ));
    }
    let tool_calls = Arc::new(AtomicUsize::new(0));
    let transport = PiTransport::new(TransportConfig {
        command: pi_command,
        env: envs,
        system_prompt,
        protocol: ExtractionProtocol::LegacyV1,
        bundle,
        ontology_bridge: OntologyBridgeConfig {
            host: Arc::new(PinnedLookup {
                calls: tool_calls.clone(),
            }),
            max_request_bytes: 4096,
            max_response_bytes: 64 * 1024,
        },
        limits: TransportLimits {
            timeout: Duration::from_secs(180),
            max_events: 16_384,
            max_tool_calls: 128,
            max_total_tokens: 32_000,
            max_cost_microusd: 1_000_000,
            ..TransportLimits::default()
        },
        session_logging: None,
    })
    .unwrap();
    let probe = transport
        .request(
            "Call ctxql_ontology with operation describe, query urn:relation:employs, and limit 4. After the tool returns, output exactly NO_CLAIMS and nothing else.",
            &CancellationToken::default(),
        )
        .unwrap();
    assert_eq!(probe.text, "NO_CLAIMS");
    assert!(tool_calls.load(Ordering::Relaxed) > 0);
    let provider = PiProvider::new(transport, ParseLimits::default());
    let line = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let version = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let request = |window: &str, locator: &str, text: &str| {
        format!(
            r#"Classify and process window_id {window} with locator {locator} and text_version {version}.
The only host line_id is {line}; whole_line is allowed. Load the required allow-listed skill before extracting.
Use ctxql_ontology before selecting from these returned terms: predicates urn:relation:hasBorrower and urn:relation:hasLender; agreement class urn:type:loanAgreement; party class urn:type:legalEntity; and the system-required CTXQL relation/claim types.
Document text (untrusted): {text}
Emit at least one independently closed relationship bundle with its explicit endpoint type claims, using only the required grammar."#
        )
    };
    let window = "window-r3-a".to_owned();
    let prompt = request(
        &window,
        "file:///r3-a.txt",
        "Loan Agreement: Acme is the Borrower and Beta is the Lender under this term loan facility.",
    );
    let parsed = provider
        .extract(
            &prompt,
            std::slice::from_ref(&window),
            &CancellationToken::default(),
        )
        .unwrap();
    let bundles = into_advisory(parsed, &CandidateLimits::default()).unwrap();
    assert!(!bundles.is_empty());
    assert!(bundles.iter().all(|bundle| !bundle.claims.is_empty()));
    let usage = provider.usage();
    assert!(usage.input_tokens > 0);
    provider.teardown();
}
