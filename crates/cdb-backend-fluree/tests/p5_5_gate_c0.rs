#[path = "p5_5_support/mod.rs"]
mod p5_5_support;

use cdb_backend_fluree::reasoning_sandbox::{reason_authorized_manifest, SandboxLimits};
use cdb_core::id::ContentHash;
use fluree_db_api::{
    config_resolver, ontology_imports, Fluree, FlureeBuilder, LedgerState, Novelty,
};
use fluree_db_core::{
    compute_schema_hierarchy_with_overlay, DatatypeConstraint, FlakeValue, GraphDbRef,
    LedgerSnapshot,
};
use fluree_db_query::{
    execute_pattern, schema_bundle::SchemaBundleOverlay, Binding, Ref, Term, TriplePattern,
    VarRegistry,
};
use fluree_db_reasoner::{reason_owl2rl, ReasoningBudget, ReasoningCache, ReasoningOptions};
use p5_5_support::{
    framed_root, quad_root, AuthorizedViewManifest, ExactTerm, ReasoningDescriptor,
    SemanticCaptureDescriptor, SourceQuad,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::Notify, task::JoinHandle};

const EX: &str = "http://example.org/";
const SCHEMA_A: &str = "http://example.org/ontology/A";
const SCHEMA_B: &str = "http://example.org/ontology/B";
const DATA_ONE: &str = "http://example.org/data/one";
const DATA_TWO: &str = "http://example.org/data/two";
const DATA_EXCLUDED: &str = "http://example.org/data/excluded";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDFS_SUBCLASS: &str = "http://www.w3.org/2000/01/rdf-schema#subClassOf";
const OWL_ONTOLOGY: &str = "http://www.w3.org/2002/07/owl#Ontology";
const OWL_IMPORTS: &str = "http://www.w3.org/2002/07/owl#imports";
const OWL_TRANSITIVE: &str = "http://www.w3.org/2002/07/owl#TransitiveProperty";
const GOVERNED_DATA_GRAPH: &str = "https://ctxql.example/vocab#governedDataGraph";

fn iri_quad(graph: &str, subject: &str, predicate: &str, object: &str) -> SourceQuad {
    SourceQuad {
        graph: graph.into(),
        subject: subject.into(),
        predicate: predicate.into(),
        object: ExactTerm::Iri(object.into()),
    }
}

fn source_fixture() -> BTreeSet<SourceQuad> {
    BTreeSet::from([
        iri_quad(
            DATA_ONE,
            &format!("{EX}alice"),
            &format!("{EX}hasAncestor"),
            &format!("{EX}bob"),
        ),
        iri_quad(
            DATA_ONE,
            &format!("{EX}alice"),
            RDF_TYPE,
            &format!("{EX}Manager"),
        ),
        SourceQuad {
            graph: DATA_ONE.into(),
            subject: format!("{EX}alice").into(),
            predicate: format!("{EX}confidence"),
            object: ExactTerm::Literal {
                lexical: "0.800".into(),
                datatype: "http://www.w3.org/2001/XMLSchema#decimal".into(),
                language: None,
            },
        },
        iri_quad(
            DATA_TWO,
            &format!("{EX}bob"),
            &format!("{EX}hasAncestor"),
            &format!("{EX}carol"),
        ),
        SourceQuad {
            graph: DATA_TWO.into(),
            subject: format!("{EX}alice").into(),
            predicate: format!("{EX}label"),
            object: ExactTerm::Literal {
                lexical: "bonjour".into(),
                datatype: "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString".into(),
                language: Some("fr".into()),
            },
        },
        SourceQuad {
            graph: DATA_TWO.into(),
            subject: format!("{EX}alice").into(),
            predicate: format!("{EX}code"),
            object: ExactTerm::Literal {
                lexical: "001".into(),
                datatype: format!("{EX}Code"),
                language: None,
            },
        },
        iri_quad(
            DATA_EXCLUDED,
            &format!("{EX}carol"),
            &format!("{EX}hasAncestor"),
            &format!("{EX}dave"),
        ),
        iri_quad(SCHEMA_A, SCHEMA_A, RDF_TYPE, OWL_ONTOLOGY),
        iri_quad(SCHEMA_A, SCHEMA_A, OWL_IMPORTS, SCHEMA_B),
        iri_quad(
            SCHEMA_A,
            &format!("{EX}Manager"),
            RDFS_SUBCLASS,
            &format!("{EX}Employee"),
        ),
        iri_quad(
            SCHEMA_A,
            &format!("{EX}hasAncestor"),
            RDF_TYPE,
            OWL_TRANSITIVE,
        ),
        iri_quad(SCHEMA_B, SCHEMA_B, RDF_TYPE, OWL_ONTOLOGY),
        iri_quad(
            SCHEMA_B,
            &format!("{EX}Employee"),
            RDFS_SUBCLASS,
            &format!("{EX}Person"),
        ),
    ])
}

fn source_graphs_trig(quads: &BTreeSet<SourceQuad>) -> String {
    let mut by_graph: BTreeMap<&str, Vec<&SourceQuad>> = BTreeMap::new();
    for quad in quads {
        by_graph.entry(&quad.graph).or_default().push(quad);
    }
    let mut trig = String::new();
    for (graph, members) in by_graph {
        trig.push_str(&format!("GRAPH <{graph}> {{\n"));
        for member in members {
            trig.push_str(&member.turtle());
            trig.push('\n');
        }
        trig.push_str("}\n");
    }
    trig
}

fn decode_binding_iri(snapshot: &LedgerSnapshot, binding: &Binding) -> Result<String, String> {
    binding
        .as_sid()
        .and_then(|sid| snapshot.decode_sid(sid))
        .ok_or_else(|| "exact_materialization_decode_failed".to_string())
}

async fn configured_iri_values(
    ledger: &LedgerState,
    graph_id: u16,
    predicate_iri: &str,
) -> Result<BTreeSet<String>, String> {
    let mut vars = VarRegistry::new();
    let subject = vars.get_or_insert("?s");
    let object = vars.get_or_insert("?o");
    let batches = execute_pattern(
        GraphDbRef::new(
            &ledger.snapshot,
            graph_id,
            ledger.novelty.as_ref(),
            ledger.t(),
        )
        .eager(),
        &vars,
        TriplePattern::new(
            Ref::Var(subject),
            Ref::Iri(Arc::from(predicate_iri)),
            Term::Var(object),
        ),
    )
    .await
    .map_err(|error| format!("ontology_configuration_invalid: {error}"))?;
    let mut values = BTreeSet::new();
    for batch in batches {
        for row in 0..batch.len() {
            values.insert(decode_binding_iri(
                &ledger.snapshot,
                batch
                    .get(row, object)
                    .ok_or_else(|| "ontology_configuration_invalid".to_string())?,
            )?);
        }
    }
    Ok(values)
}

async fn read_graph_quads(
    ledger: &LedgerState,
    graph_id: u16,
    graph_label: &str,
) -> Result<BTreeSet<SourceQuad>, String> {
    let mut vars = VarRegistry::new();
    let subject = vars.get_or_insert("?s");
    let predicate = vars.get_or_insert("?p");
    let object = vars.get_or_insert("?o");
    let batches = execute_pattern(
        GraphDbRef::new(
            &ledger.snapshot,
            graph_id,
            ledger.novelty.as_ref(),
            ledger.t(),
        )
        .eager(),
        &vars,
        TriplePattern::new(Ref::Var(subject), Ref::Var(predicate), Term::Var(object)),
    )
    .await
    .map_err(|error| format!("exact_materialization_read_failed: {error}"))?;
    let mut quads = BTreeSet::new();
    for batch in batches {
        for row in 0..batch.len() {
            let object_binding = batch
                .get(row, object)
                .ok_or_else(|| "exact_materialization_decode_failed".to_string())?;
            let object = if object_binding.as_sid().is_some() {
                ExactTerm::Iri(decode_binding_iri(&ledger.snapshot, object_binding)?)
            } else {
                let (value, datatype) = object_binding
                    .as_lit()
                    .ok_or_else(|| "exact_materialization_decode_failed".to_string())?;
                let lexical = match value {
                    FlakeValue::String(value) | FlakeValue::Json(value) => value.clone(),
                    FlakeValue::Decimal(value) => value.to_plain_string(),
                    _ => return Err("unsupported_exact_literal".into()),
                };
                let (datatype, language) = match datatype {
                    DatatypeConstraint::Explicit(datatype) => (
                        ledger
                            .snapshot
                            .decode_sid(datatype)
                            .ok_or_else(|| "exact_materialization_decode_failed".to_string())?,
                        None,
                    ),
                    DatatypeConstraint::LangTag(language) => (
                        "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString".into(),
                        Some(language.to_string()),
                    ),
                };
                ExactTerm::Literal {
                    lexical,
                    datatype,
                    language,
                }
            };
            quads.insert(SourceQuad {
                graph: graph_label.into(),
                subject: decode_binding_iri(
                    &ledger.snapshot,
                    batch
                        .get(row, subject)
                        .ok_or_else(|| "exact_materialization_decode_failed".to_string())?,
                )?
                .into(),
                predicate: decode_binding_iri(
                    &ledger.snapshot,
                    batch
                        .get(row, predicate)
                        .ok_or_else(|| "exact_materialization_decode_failed".to_string())?,
                )?,
                object,
            });
        }
    }
    Ok(quads)
}

fn genesis(ledger: &str) -> LedgerState {
    LedgerState::new(LedgerSnapshot::genesis(ledger), Novelty::new(0))
}

async fn apply_trig(fluree: &Fluree, ledger: LedgerState, trig: &str) -> LedgerState {
    fluree
        .stage_owned(ledger)
        .upsert_turtle(trig)
        .execute()
        .await
        .expect("TriG stage")
        .ledger
}

fn strict_reasoning_config(
    config: &fluree_db_core::ledger_config::LedgerConfig,
) -> Result<fluree_db_core::ledger_config::ReasoningDefaults, String> {
    let effective = config_resolver::resolve_effective_config(config, None);
    let reasoning = effective
        .reasoning
        .ok_or_else(|| "configured reasoning defaults are required".to_string())?;
    let source = reasoning
        .schema_source
        .as_ref()
        .ok_or_else(|| "configured schema source is required".to_string())?;
    if source.graph_selector.as_deref().is_none_or(str::is_empty) {
        return Err("configured schema source requires an explicit graph selector".into());
    }
    Ok(reasoning)
}

async fn prepare_authorized_semantic_view(
    ledger: &LedgerState,
) -> Result<AuthorizedViewManifest, String> {
    let config = config_resolver::resolve_ledger_config(
        &ledger.snapshot,
        ledger.novelty.as_ref(),
        ledger.t(),
    )
    .await
    .map_err(|error| format!("ontology_configuration_invalid: {error}"))?
    .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
    let effective = config_resolver::resolve_effective_config(&config, None);
    if effective.policy.is_some() {
        return Err("configured_policy_requires_e0_authority".into());
    }
    let reasoning = strict_reasoning_config(&config)?;
    let schema_source = reasoning
        .schema_source
        .as_ref()
        .and_then(|source| source.graph_selector.clone())
        .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
    let config_graph = fluree_db_core::graph_registry::config_graph_iri(&ledger.snapshot.ledger_id);
    let config_graph_id = ledger
        .snapshot
        .graph_registry
        .graph_id_for_iri(&config_graph)
        .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
    let governed_graphs =
        configured_iri_values(ledger, config_graph_id, GOVERNED_DATA_GRAPH).await?;
    if governed_graphs.is_empty() {
        return Err("ontology_configuration_invalid".into());
    }
    let mut data_quads = BTreeSet::new();
    for graph in &governed_graphs {
        let graph_id = ledger
            .snapshot
            .graph_registry
            .graph_id_for_iri(graph)
            .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
        data_quads.extend(read_graph_quads(ledger, graph_id, graph).await?);
    }
    let bundle = ontology_imports::resolve_schema_bundle(
        &ledger.snapshot,
        ledger.novelty.as_ref(),
        ledger.t(),
        &reasoning,
    )
    .await
    .map_err(|error| format!("ontology_configuration_invalid: {error}"))?
    .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
    let mut schema_graphs = BTreeSet::new();
    let mut schema_quads = BTreeSet::new();
    for graph_id in &bundle.sources {
        let graph = ledger
            .snapshot
            .graph_registry
            .iri_for_graph_id(*graph_id)
            .ok_or_else(|| "ontology_configuration_invalid".to_string())?
            .to_string();
        schema_graphs.insert(graph.clone());
        schema_quads.extend(read_graph_quads(ledger, *graph_id, &graph).await?);
    }
    let governed_commitment = governed_graphs
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\u{0}");
    let schema_commitment = schema_graphs
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\u{0}");
    let follow_imports = reasoning.follow_owl_imports.unwrap_or(false);
    let follow_commitment = follow_imports.to_string();
    let historical_config_root = framed_root(
        "ctxql-historical-config/v1",
        [
            ("schema-source", schema_source.as_str()),
            ("follow-imports", follow_commitment.as_str()),
            ("governed-data", governed_commitment.as_str()),
            ("schema-graphs", schema_commitment.as_str()),
        ],
    );
    let policy_dependency_root = framed_root(
        "ctxql-semantic-policy/v1",
        [
            ("ledger", ledger.snapshot.ledger_id.as_str()),
            ("principal", "did:example:alice"),
            ("action", "ctxql:query"),
            ("mode", "unrestricted:no-configured-policy"),
        ],
    );
    let capture = SemanticCaptureDescriptor {
        ledger: ledger.snapshot.ledger_id.clone(),
        requested_as_of: format!("t:{}", ledger.t()),
        t: ledger.t(),
        commit_cid: ledger
            .head_commit_id
            .as_ref()
            .ok_or_else(|| "semantic_capture_incomplete".to_string())?
            .to_string(),
    };
    Ok(AuthorizedViewManifest::seal(
        capture,
        ReasoningDescriptor {
            schema_source,
            follow_owl_imports: follow_imports,
            schema_graphs,
        },
        data_quads,
        schema_quads,
        BTreeSet::new(),
        historical_config_root,
        policy_dependency_root,
        "terminal:source-authoritative-e0",
    ))
}

fn reasoning_from_manifest(
    manifest: &AuthorizedViewManifest,
) -> fluree_db_core::ledger_config::ReasoningDefaults {
    fluree_db_core::ledger_config::ReasoningDefaults {
        modes: Some(vec!["owl2rl".into()]),
        schema_source: Some(fluree_db_core::ledger_config::GraphSourceRef {
            ledger: None,
            graph_selector: Some(manifest.reasoning.schema_source.clone()),
            at_t: None,
            trust_policy: None,
            rollback_guard: None,
        }),
        follow_owl_imports: Some(manifest.reasoning.follow_owl_imports),
        ..Default::default()
    }
}

#[derive(Debug, Eq, PartialEq)]
struct NormalizedDiagnostics {
    iterations: usize,
    facts_derived: usize,
    capped: bool,
    capped_reason: Option<String>,
    rules_fired: BTreeMap<String, usize>,
}

fn normalized(result: &fluree_db_reasoner::ReasoningResult) -> NormalizedDiagnostics {
    NormalizedDiagnostics {
        iterations: result.diagnostics.iterations,
        facts_derived: result.diagnostics.facts_derived,
        capped: result.diagnostics.capped,
        capped_reason: result.diagnostics.capped_reason.clone(),
        rules_fired: result
            .diagnostics
            .rules_fired
            .iter()
            .map(|(rule, count)| (rule.clone(), *count))
            .collect(),
    }
}

fn diagnostics_commitment(diagnostics: &NormalizedDiagnostics) -> String {
    let rules = diagnostics
        .rules_fired
        .iter()
        .map(|(rule, count)| format!("{}:{rule}:{count}", rule.len()))
        .collect::<Vec<_>>()
        .join("\u{0}");
    format!(
        "{}:{}:{}:{}:{rules}",
        diagnostics.iterations,
        diagnostics.facts_derived,
        diagnostics.capped,
        diagnostics.capped_reason.as_deref().unwrap_or("")
    )
}

fn derived_iri_triples(
    ledger: &LedgerState,
    result: &fluree_db_reasoner::ReasoningResult,
) -> BTreeSet<(String, String, String)> {
    result
        .overlay
        .flakes_spot()
        .iter()
        .filter_map(|flake| {
            let FlakeValue::Ref(object) = &flake.o else {
                return None;
            };
            Some((
                ledger.snapshot.decode_sid(&flake.s)?,
                ledger.snapshot.decode_sid(&flake.p)?,
                ledger.snapshot.decode_sid(object)?,
            ))
        })
        .collect()
}

struct SandboxOwner {
    _fluree: Fluree,
    ledger: LedgerState,
    dropped: Arc<AtomicBool>,
}

impl Drop for SandboxOwner {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct TaskGuard(Arc<AtomicBool>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct SandboxBuildTask {
    handle: Option<JoinHandle<Result<SandboxOwner, String>>>,
}

impl SandboxBuildTask {
    async fn join(mut self) -> Result<SandboxOwner, String> {
        let result = self
            .handle
            .as_mut()
            .expect("single join")
            .await
            .map_err(|_| "sandbox_task_failed".to_string())?;
        self.handle.take();
        result
    }
}

impl Drop for SandboxBuildTask {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

fn spawn_sandbox_build(
    manifest: AuthorizedViewManifest,
    owner_dropped: Arc<AtomicBool>,
    task_finished: Arc<AtomicBool>,
    gate: Option<Arc<Notify>>,
    panic_after_gate: bool,
) -> SandboxBuildTask {
    let task_guard = TaskGuard(task_finished);
    SandboxBuildTask {
        handle: Some(tokio::spawn(async move {
            let _guard = task_guard;
            if let Some(gate) = gate {
                gate.notified().await;
            }
            assert!(!panic_after_gate, "sandbox task panic probe");
            build_sandbox(&manifest, owner_dropped).await
        })),
    }
}

async fn build_sandbox(
    manifest: &AuthorizedViewManifest,
    dropped: Arc<AtomicBool>,
) -> Result<SandboxOwner, String> {
    manifest.validate()?;
    let validate_iri = |iri: &str| {
        if iri.starts_with("_:") {
            Err("blank_node_not_supported".to_string())
        } else {
            Ok(())
        }
    };
    let mut trig = String::new();
    // Source graph identity remains in each manifest member and its roots, but
    // authorized data is deterministically deduplicated into graph 0.
    for quad in &manifest.data_quads {
        validate_iri(
            quad.subject_iri()
                .ok_or_else(|| "blank_node_not_supported".to_string())?,
        )?;
        validate_iri(&quad.predicate)?;
        if let ExactTerm::Iri(iri) = &quad.object {
            validate_iri(iri)?;
        }
        trig.push_str(&quad.turtle());
        trig.push('\n');
    }
    let mut by_graph: BTreeMap<&str, Vec<&SourceQuad>> = BTreeMap::new();
    for quad in &manifest.schema_quads {
        validate_iri(&quad.graph)?;
        validate_iri(
            quad.subject_iri()
                .ok_or_else(|| "blank_node_not_supported".to_string())?,
        )?;
        validate_iri(&quad.predicate)?;
        if let ExactTerm::Iri(iri) = &quad.object {
            validate_iri(iri)?;
        }
        by_graph.entry(&quad.graph).or_default().push(quad);
    }
    for (graph, quads) in by_graph {
        trig.push_str(&format!("GRAPH <{graph}> {{\n"));
        for quad in quads {
            trig.push_str(&quad.turtle());
            trig.push('\n');
        }
        trig.push_str("}\n");
    }

    let fluree = FlureeBuilder::memory().build_memory();
    let ledger_id = "ctxql/p5-5-c0-sandbox:main";
    let ledger = fluree
        .stage_owned(genesis(ledger_id))
        .upsert_turtle(&trig)
        .execute()
        .await
        .map_err(|error| format!("sandbox_materialization_failed: {error}"))?
        .ledger;
    let union_label = "urn:ctxql:sandbox-union";
    let actual_union = read_graph_quads(&ledger, 0, union_label).await?;
    let expected_union: BTreeSet<_> = manifest
        .data_quads
        .iter()
        .cloned()
        .map(|mut quad| {
            quad.graph = union_label.into();
            quad
        })
        .collect();
    if actual_union != expected_union {
        return Err("sandbox_materialization_mismatch".into());
    }
    for graph in &manifest.reasoning.schema_graphs {
        let graph_id = ledger
            .snapshot
            .graph_registry
            .graph_id_for_iri(graph)
            .ok_or_else(|| "sandbox_materialization_mismatch".to_string())?;
        let actual = read_graph_quads(&ledger, graph_id, graph).await?;
        let expected: BTreeSet<_> = manifest
            .schema_quads
            .iter()
            .filter(|quad| &quad.graph == graph)
            .cloned()
            .collect();
        if actual != expected {
            return Err("sandbox_materialization_mismatch".into());
        }
    }
    Ok(SandboxOwner {
        _fluree: fluree,
        ledger,
        dropped,
    })
}

async fn run_sandbox(
    owner: &SandboxOwner,
    manifest: &AuthorizedViewManifest,
    budget: ReasoningBudget,
    budget_identity: &str,
) -> (
    BTreeSet<(String, String, String)>,
    NormalizedDiagnostics,
    ContentHash,
) {
    let reasoning = reasoning_from_manifest(manifest);
    let bundle = ontology_imports::resolve_schema_bundle(
        &owner.ledger.snapshot,
        owner.ledger.novelty.as_ref(),
        owner.ledger.t(),
        &reasoning,
    )
    .await
    .expect("schema closure")
    .expect("configured schema source");
    assert_eq!(bundle.sources.len(), 2, "A imports B exactly once");

    let flakes = ontology_imports::get_or_build_schema_bundle_flakes(
        &owner.ledger.snapshot,
        owner.ledger.novelty.as_ref(),
        &bundle,
    )
    .await
    .expect("standard schema bundle flakes");
    let overlay = SchemaBundleOverlay::new(owner.ledger.novelty.as_ref(), flakes);
    let hierarchy =
        compute_schema_hierarchy_with_overlay(&owner.ledger.snapshot, &overlay, owner.ledger.t())
            .await
            .expect("overlay-aware hierarchy")
            .expect("schema hierarchy");
    let manager = owner
        .ledger
        .snapshot
        .encode_iri(&format!("{EX}Manager"))
        .expect("Manager SID");
    let person = owner
        .ledger
        .snapshot
        .encode_iri(&format!("{EX}Person"))
        .expect("Person SID");
    assert!(
        hierarchy.subclasses_of(&person).contains(&manager),
        "imported schema participates in the same composed overlay"
    );

    let result = reason_owl2rl(
        GraphDbRef::new(&owner.ledger.snapshot, 0, &overlay, owner.ledger.t()),
        &ReasoningOptions::with_budget(budget),
        &ReasoningCache::new(1),
    )
    .await
    .expect("direct OWL2-RL");
    let diagnostics = normalized(&result);
    let diagnostics_identity = diagnostics_commitment(&diagnostics);
    let prepared_root = framed_root(
        "ctxql-prepared-ontology/v1",
        [
            (
                "execution-manifest",
                manifest.execution_manifest_root.0.as_str(),
            ),
            ("materializer", "ctxql-fluree-authorized-union/v1"),
            (
                "reasoner-profile",
                manifest.ontology_profile.identity.as_str(),
            ),
            (
                "profile-result",
                manifest.ontology_profile.result_root.as_str(),
            ),
            ("budget", budget_identity),
            ("diagnostics", diagnostics_identity.as_str()),
        ],
    );
    (
        derived_iri_triples(&owner.ledger, &result),
        diagnostics,
        prepared_root,
    )
}

#[tokio::test]
async fn strict_configured_bundle_and_scoped_authorized_sandbox_are_composable() {
    let source = FlureeBuilder::memory().build_memory();
    let source_id = "ctxql/p5-5-c0-source:main";
    let config_graph = format!("urn:fluree:{source_id}#config");
    let source_ledger = apply_trig(
        &source,
        genesis(source_id),
        &format!(
            r#"
            @prefix f: <https://ns.flur.ee/db#> .
            @prefix owl: <http://www.w3.org/2002/07/owl#> .
            @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
            @prefix ctxql: <https://ctxql.example/vocab#> .

            GRAPH <{SCHEMA_A}> {{
                <{SCHEMA_A}> rdf:type owl:Ontology ; owl:imports <{SCHEMA_B}> .
            }}
            GRAPH <{SCHEMA_B}> {{ <{SCHEMA_B}> rdf:type owl:Ontology . }}
            GRAPH <{config_graph}> {{
                <urn:ctxql:config> rdf:type f:LedgerConfig ;
                    f:reasoningDefaults <urn:ctxql:reasoning> ;
                    ctxql:governedDataGraph <{DATA_ONE}>, <{DATA_TWO}> .
                <urn:ctxql:reasoning> f:reasoningModes f:owl2rl ;
                    f:schemaSource <urn:ctxql:schema-ref> ;
                    f:followOwlImports true .
                <urn:ctxql:schema-ref> rdf:type f:GraphRef ;
                    f:graphSource <urn:ctxql:schema-source> .
                <urn:ctxql:schema-source> f:graphSelector <{SCHEMA_A}> .
            }}
            "#
        ),
    )
    .await;
    let source_fixture = source_fixture();
    let source_ledger =
        apply_trig(&source, source_ledger, &source_graphs_trig(&source_fixture)).await;

    let config = config_resolver::resolve_ledger_config(
        &source_ledger.snapshot,
        source_ledger.novelty.as_ref(),
        source_ledger.t(),
    )
    .await
    .expect("strict config read")
    .expect("configured source");
    let reasoning = strict_reasoning_config(&config).expect("strict reasoning defaults");
    assert_eq!(
        reasoning
            .schema_source
            .as_ref()
            .and_then(|source| source.graph_selector.as_deref()),
        Some(SCHEMA_A)
    );
    assert_eq!(reasoning.follow_owl_imports, Some(true));

    let source_bundle = ontology_imports::resolve_schema_bundle(
        &source_ledger.snapshot,
        source_ledger.novelty.as_ref(),
        source_ledger.t(),
        &reasoning,
    )
    .await
    .expect("historical configured closure")
    .expect("source closure");
    assert_eq!(source_bundle.to_t, source_ledger.t());
    assert_eq!(source_bundle.sources.len(), 2);
    let historical_flakes = ontology_imports::get_or_build_schema_bundle_flakes(
        &source_ledger.snapshot,
        source_ledger.novelty.as_ref(),
        &source_bundle,
    )
    .await
    .expect("historical bundle flakes");
    let advanced_source = apply_trig(
        &source,
        source_ledger.clone(),
        &format!(
            r#"@prefix ex: <{EX}> .
               @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
               GRAPH <{SCHEMA_B}> {{ ex:Person rdfs:subClassOf ex:Agent . }}"#
        ),
    )
    .await;
    let advanced_config = config_resolver::resolve_ledger_config(
        &advanced_source.snapshot,
        advanced_source.novelty.as_ref(),
        advanced_source.t(),
    )
    .await
    .expect("advanced config read")
    .expect("advanced config");
    let advanced_reasoning = strict_reasoning_config(&advanced_config).expect("advanced reasoning");
    let advanced_bundle = ontology_imports::resolve_schema_bundle(
        &advanced_source.snapshot,
        advanced_source.novelty.as_ref(),
        advanced_source.t(),
        &advanced_reasoning,
    )
    .await
    .expect("advanced closure")
    .expect("advanced source closure");
    let advanced_flakes = ontology_imports::get_or_build_schema_bundle_flakes(
        &advanced_source.snapshot,
        advanced_source.novelty.as_ref(),
        &advanced_bundle,
    )
    .await
    .expect("advanced bundle flakes");
    assert!(advanced_source.t() > source_ledger.t());
    assert!(advanced_flakes.len() > historical_flakes.len());
    let historical_again = ontology_imports::get_or_build_schema_bundle_flakes(
        &source_ledger.snapshot,
        source_ledger.novelty.as_ref(),
        &source_bundle,
    )
    .await
    .expect("repeat historical bundle flakes");
    assert_eq!(historical_again.len(), historical_flakes.len());

    assert!(source_fixture
        .iter()
        .any(|quad| quad.graph == DATA_EXCLUDED));
    let manifest = prepare_authorized_semantic_view(&source_ledger)
        .await
        .expect("E0 source-authoritative manifest");
    assert!(!manifest
        .data_quads
        .iter()
        .any(|quad| quad.graph == DATA_EXCLUDED));
    assert!(manifest
        .schema_quads
        .iter()
        .any(|quad| quad.predicate == RDFS_SUBCLASS));
    assert_eq!(manifest.data_root, quad_root(&manifest.data_quads));
    assert_eq!(manifest.schema_root, quad_root(&manifest.schema_quads));
    assert!(!manifest.authorized_premise_root.0.as_str().is_empty());
    assert!(!manifest.execution_manifest_root.0.as_str().is_empty());
    assert!(!manifest.historical_config_root.as_str().is_empty());
    assert!(!manifest.policy_dependency_root.as_str().is_empty());

    let drop_one = Arc::new(AtomicBool::new(false));
    let task_one_finished = Arc::new(AtomicBool::new(false));
    let owner_one = spawn_sandbox_build(
        manifest.clone(),
        Arc::clone(&drop_one),
        Arc::clone(&task_one_finished),
        None,
        false,
    )
    .join()
    .await
    .expect("sealed manifest materialization");
    assert!(task_one_finished.load(Ordering::SeqCst));
    let union_label = "urn:ctxql:sandbox-union";
    let exact_union = read_graph_quads(&owner_one.ledger, 0, union_label)
        .await
        .expect("exact sandbox union readback");
    let expected_union: BTreeSet<_> = manifest
        .data_quads
        .iter()
        .cloned()
        .map(|mut quad| {
            quad.graph = union_label.into();
            quad
        })
        .collect();
    assert_eq!(exact_union, expected_union);
    let (first_facts, first_diagnostics, first_prepared_root) = run_sandbox(
        &owner_one,
        &manifest,
        ReasoningBudget::new(Duration::from_secs(2), 1024, 1024 * 1024),
        "seconds=2;facts=1024;memory=1048576",
    )
    .await;
    assert!(!first_diagnostics.capped, "complete direct diagnostics");
    assert!(first_facts.contains(&(
        format!("{EX}alice"),
        format!("{EX}hasAncestor"),
        format!("{EX}carol")
    )));
    assert!(!first_facts
        .iter()
        .any(|(_, _, object)| object == &format!("{EX}dave")));
    let promoted = reason_authorized_manifest(
        &manifest,
        SandboxLimits {
            max_input_facts: 1024,
            max_input_bytes: 1024 * 1024,
            materialization_timeout: Duration::from_secs(2),
            reasoning: ReasoningBudget::new(Duration::from_secs(2), 1024, 1024 * 1024),
            budget_identity: "seconds=2;facts=1024;memory=1048576".into(),
        },
    )
    .await
    .expect_err("historical manifest must not execute under the current backend identity");
    assert_eq!(promoted.kind, cdb_core::ErrorKind::Unsupported);
    // Current-profile production parity is covered independently in
    // p5_6_production_parity and p5_6_reasoning_sandbox. This fixture seals
    // the archival v1 profile and must retain its unavailable-executor result.
    drop(owner_one);
    assert!(drop_one.load(Ordering::SeqCst), "sandbox owner dropped");

    let drop_two = Arc::new(AtomicBool::new(false));
    let task_two_finished = Arc::new(AtomicBool::new(false));
    let owner_two = spawn_sandbox_build(
        manifest.clone(),
        Arc::clone(&drop_two),
        Arc::clone(&task_two_finished),
        None,
        false,
    )
    .join()
    .await
    .expect("second sealed manifest materialization");
    assert!(task_two_finished.load(Ordering::SeqCst));
    let (second_facts, second_diagnostics, second_prepared_root) = run_sandbox(
        &owner_two,
        &manifest,
        ReasoningBudget::new(Duration::from_secs(2), 1024, 1024 * 1024),
        "seconds=2;facts=1024;memory=1048576",
    )
    .await;
    assert_eq!(first_facts, second_facts);
    assert_eq!(first_diagnostics, second_diagnostics);
    assert_eq!(first_prepared_root, second_prepared_root);
    drop(owner_two);
    assert!(drop_two.load(Ordering::SeqCst), "second owner dropped");

    let capped_drop = Arc::new(AtomicBool::new(false));
    let capped_finished = Arc::new(AtomicBool::new(false));
    let capped_owner = spawn_sandbox_build(
        manifest.clone(),
        Arc::clone(&capped_drop),
        Arc::clone(&capped_finished),
        None,
        false,
    )
    .join()
    .await
    .expect("capped sandbox materialization");
    assert!(capped_finished.load(Ordering::SeqCst));
    let (_, capped, _) = run_sandbox(
        &capped_owner,
        &manifest,
        ReasoningBudget::new(Duration::from_secs(2), 1, 1024),
        "seconds=2;facts=1;memory=1024",
    )
    .await;
    assert!(
        capped.capped,
        "tight direct-reasoner budget must report incompleteness"
    );
    assert!(capped.capped_reason.is_some());
    drop(capped_owner);
    assert!(capped_drop.load(Ordering::SeqCst));

    let mut blank_data = manifest.data_quads.clone();
    blank_data.insert(iri_quad(
        DATA_ONE,
        "_:unstable",
        &format!("{EX}value"),
        &format!("{EX}object"),
    ));
    let blank_node_manifest = AuthorizedViewManifest::seal(
        manifest.capture.clone(),
        manifest.reasoning.clone(),
        blank_data,
        manifest.schema_quads.clone(),
        manifest.visible_supports.clone(),
        manifest.historical_config_root.clone(),
        manifest.policy_dependency_root.clone(),
        "blank-node-probe",
    );
    let blank_drop = Arc::new(AtomicBool::new(false));
    let blank_error = match build_sandbox(&blank_node_manifest, Arc::clone(&blank_drop)).await {
        Ok(_) => panic!("unstable blank-node identity must fail before materialization"),
        Err(error) => error,
    };
    assert_eq!(blank_error, "blank_node_not_supported");
    assert!(!blank_drop.load(Ordering::SeqCst));
}

async fn wait_for_task_drop(flag: &AtomicBool) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !flag.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("sandbox task must terminate");
}

fn task_fixture_manifest() -> AuthorizedViewManifest {
    let members = source_fixture();
    let data_quads = members
        .iter()
        .filter(|quad| matches!(quad.graph.as_str(), DATA_ONE | DATA_TWO))
        .cloned()
        .collect();
    let schema_quads = members
        .iter()
        .filter(|quad| matches!(quad.graph.as_str(), SCHEMA_A | SCHEMA_B))
        .cloned()
        .collect();
    AuthorizedViewManifest::seal(
        SemanticCaptureDescriptor {
            ledger: "ctxql/p5-5-c0-task-fixture:main".into(),
            requested_as_of: "t:1".into(),
            t: 1,
            commit_cid: "cid:task-fixture".into(),
        },
        ReasoningDescriptor {
            schema_source: SCHEMA_A.into(),
            follow_owl_imports: true,
            schema_graphs: BTreeSet::from([SCHEMA_A.into(), SCHEMA_B.into()]),
        },
        data_quads,
        schema_quads,
        BTreeSet::new(),
        ContentHash::of_bytes(b"task-fixture-config"),
        ContentHash::of_bytes(b"task-fixture-policy"),
        "task-fixture-terminal",
    )
}

#[tokio::test]
async fn sandbox_tasks_abort_or_join_on_every_probed_exit() {
    let manifest = task_fixture_manifest();

    let cancelled_finished = Arc::new(AtomicBool::new(false));
    let cancelled = spawn_sandbox_build(
        manifest.clone(),
        Arc::new(AtomicBool::new(false)),
        Arc::clone(&cancelled_finished),
        Some(Arc::new(Notify::new())),
        false,
    );
    drop(cancelled);
    wait_for_task_drop(&cancelled_finished).await;

    let timeout_finished = Arc::new(AtomicBool::new(false));
    let timeout_task = spawn_sandbox_build(
        manifest.clone(),
        Arc::new(AtomicBool::new(false)),
        Arc::clone(&timeout_finished),
        Some(Arc::new(Notify::new())),
        false,
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(1), timeout_task.join())
            .await
            .is_err()
    );
    wait_for_task_drop(&timeout_finished).await;

    let panic_finished = Arc::new(AtomicBool::new(false));
    let panic_error = match spawn_sandbox_build(
        manifest.clone(),
        Arc::new(AtomicBool::new(false)),
        Arc::clone(&panic_finished),
        None,
        true,
    )
    .join()
    .await
    {
        Ok(_) => panic!("panic path must fail"),
        Err(error) => error,
    };
    assert_eq!(panic_error, "sandbox_task_failed");
    assert!(panic_finished.load(Ordering::SeqCst));

    // Freshness is owned by the outer E0 coordinator. A detected change aborts
    // the manifest-only C0 task rather than passing policy authority into C0.
    let policy_change_finished = Arc::new(AtomicBool::new(false));
    let policy_change = spawn_sandbox_build(
        manifest.clone(),
        Arc::new(AtomicBool::new(false)),
        Arc::clone(&policy_change_finished),
        Some(Arc::new(Notify::new())),
        false,
    );
    drop(policy_change);
    wait_for_task_drop(&policy_change_finished).await;

    let mut invalid_data = manifest.data_quads.clone();
    invalid_data.insert(iri_quad(
        DATA_ONE,
        "_:unstable",
        &format!("{EX}value"),
        &format!("{EX}object"),
    ));
    let invalid = AuthorizedViewManifest::seal(
        manifest.capture.clone(),
        manifest.reasoning.clone(),
        invalid_data,
        manifest.schema_quads.clone(),
        manifest.visible_supports.clone(),
        manifest.historical_config_root.clone(),
        manifest.policy_dependency_root.clone(),
        "materialization-error-probe",
    );
    let error_finished = Arc::new(AtomicBool::new(false));
    let materialization_error = match spawn_sandbox_build(
        invalid,
        Arc::new(AtomicBool::new(false)),
        Arc::clone(&error_finished),
        None,
        false,
    )
    .join()
    .await
    {
        Ok(_) => panic!("materialization error must propagate"),
        Err(error) => error,
    };
    assert_eq!(materialization_error, "blank_node_not_supported");
    assert!(error_finished.load(Ordering::SeqCst));
}

#[tokio::test]
async fn malformed_configured_schema_source_fails_instead_of_using_defaults() {
    let fluree = FlureeBuilder::memory().build_memory();
    let ledger_id = "ctxql/p5-5-c0-malformed:main";
    let config_graph = format!("urn:fluree:{ledger_id}#config");
    let ledger = apply_trig(
        &fluree,
        genesis(ledger_id),
        &format!(
            r#"
            @prefix f: <https://ns.flur.ee/db#> .
            @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
            GRAPH <{config_graph}> {{
                <urn:ctxql:config> rdf:type f:LedgerConfig ;
                    f:reasoningDefaults <urn:ctxql:reasoning> .
                <urn:ctxql:reasoning> f:reasoningModes f:owl2rl ;
                    f:schemaSource <urn:ctxql:broken-schema-ref> .
                <urn:ctxql:broken-schema-ref> rdf:type f:GraphRef .
            }}
            "#
        ),
    )
    .await;

    let config = config_resolver::resolve_ledger_config(
        &ledger.snapshot,
        ledger.novelty.as_ref(),
        ledger.t(),
    )
    .await
    .expect("public config read")
    .expect("malformed config remains visible");
    let error = strict_reasoning_config(&config)
        .expect_err("adapter must reject the upstream resolver's implicit default graph");
    assert_eq!(
        error,
        "configured schema source requires an explicit graph selector"
    );
}
