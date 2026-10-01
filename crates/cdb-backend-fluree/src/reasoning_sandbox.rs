//! Disposable manifest-only native reasoning sandbox.

use crate::{
    authorized_view::{
        build_reasoner_input, framed_root, quad_root, AuthorizedViewManifest, ExactTerm,
        SourceQuad, STRUCTURAL_NODE_IRI_PREFIX,
    },
    current_reasoning_profile::{classify_current_reasoning_profile, CURRENT_REASONING_PROFILE_ID},
    exact_term::{
        decode_flake_object, decode_iri as decode_exact_iri, decode_node,
        decode_term as decode_exact_term,
    },
    ontology_profile::classify_ontology_bundle,
    ontology_profile_v2::{
        classify_ontology_bundle_v2, OntologyProfileLimits, ONTOLOGY_PROFILE_V2_ID,
    },
    ontology_profile_v3::ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID,
};
use cdb_core::{
    contracts::PreparedOntologyDescriptor,
    id::{ContentHash, VersionId},
    snapshot::SnapshotRef,
    Error, ErrorKind, Result,
};
use fluree_db_api::{ontology_imports, FlureeBuilder, LedgerState, Novelty};
use fluree_db_core::{
    compute_schema_hierarchy_with_overlay, GraphDbRef, IndexSchema, LedgerSnapshot, SchemaHierarchy,
};
use fluree_db_query::{
    execute_pattern,
    schema_bundle::{SchemaBundleFlakes, SchemaBundleOverlay},
    Ref, Term, TriplePattern, VarRegistry,
};
use fluree_db_reasoner::{reason_owl2rl, ReasoningBudget, ReasoningCache, ReasoningOptions};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

static SANDBOX_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Owns every native object in one disposable reasoning scope. Nothing in a
/// `PreparedOntology` borrows from this owner. Rust drops this scope on normal
/// return, error propagation, a reasoning cap, timeout (which drops the inner
/// future), and caller cancellation. Drop order is explicit: ledger state
/// first, then its private in-memory client.
struct SandboxScope {
    ledger: Option<LedgerState>,
    fluree: Option<fluree_db_api::Fluree>,
    #[cfg(test)]
    teardown_probe: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

impl SandboxScope {
    fn new() -> Self {
        Self {
            ledger: None,
            fluree: Some(FlureeBuilder::memory().build_memory()),
            #[cfg(test)]
            teardown_probe: None,
        }
    }

    fn fluree(&self) -> &fluree_db_api::Fluree {
        self.fluree.as_ref().expect("live sandbox client")
    }

    fn install_ledger(&mut self, ledger: LedgerState) {
        self.ledger = Some(ledger);
    }

    fn ledger(&self) -> &LedgerState {
        self.ledger.as_ref().expect("materialized sandbox ledger")
    }

    #[cfg(test)]
    fn with_teardown_probe(teardown_probe: std::sync::Arc<std::sync::atomic::AtomicUsize>) -> Self {
        let mut scope = Self::new();
        scope.teardown_probe = Some(teardown_probe);
        scope
    }
}

impl Drop for SandboxScope {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(probe) = &self.teardown_probe {
            probe.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        // Fields are then dropped in declaration order. In particular, avoid
        // `Option::take` here: moving Fluree's large ledger state onto the test
        // thread stack during teardown can itself overflow that stack.
    }
}

#[derive(Clone, Debug)]
pub struct SandboxLimits {
    pub max_input_facts: usize,
    pub max_input_bytes: usize,
    pub materialization_timeout: Duration,
    pub reasoning: ReasoningBudget,
    pub budget_identity: String,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        let timeout = Duration::from_secs(10);
        let facts = 100_000;
        let bytes = 64 * 1024 * 1024;
        Self {
            max_input_facts: facts,
            max_input_bytes: bytes,
            materialization_timeout: timeout,
            reasoning: ReasoningBudget::new(timeout, facts, bytes),
            budget_identity: format!("seconds=10;facts={facts};memory={bytes}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedDiagnostics {
    pub iterations: usize,
    pub facts_derived: usize,
    pub capped: bool,
    pub capped_reason: Option<String>,
    pub rules_fired: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PreparedFact {
    pub subject: String,
    pub predicate: String,
    pub object: ExactTerm,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedOntology {
    pub asserted_data_quads: BTreeSet<SourceQuad>,
    pub inferred_facts: BTreeSet<PreparedFact>,
    /// Historical P5.5 lookup projection retained for source compatibility.
    pub inferred_iri_triples: BTreeSet<(String, String, String)>,
    pub class_entailments: BTreeSet<(String, String)>,
    pub property_entailments: BTreeSet<(String, String)>,
    pub diagnostics: NormalizedDiagnostics,
    pub diagnostics_root: ContentHash,
    pub prepared_root: ContentHash,
    pub budget_identity: ContentHash,
    pub materialization_limits_identity: ContentHash,
    pub reasoning_limits_identity: ContentHash,
}

impl PreparedOntology {
    pub fn entails_class(&self, actual: &str, target: &str) -> bool {
        actual == target
            || self
                .class_entailments
                .contains(&(actual.to_string(), target.to_string()))
    }

    pub fn entails_property(&self, actual: &str, target: &str) -> bool {
        actual == target
            || self
                .property_entailments
                .contains(&(actual.to_string(), target.to_string()))
    }

    pub fn has_type(&self, subject: &str, class: &str) -> bool {
        self.inferred_facts.contains(&PreparedFact {
            subject: subject.to_string(),
            predicate: "http://www.w3.org/1999/02/22-rdf-syntax-ns#type".to_string(),
            object: ExactTerm::Iri(class.to_string()),
        }) || self.asserted_data_quads.iter().any(|quad| {
            quad.subject == subject
                && quad.predicate == "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
                && quad.object == ExactTerm::Iri(class.to_string())
        })
    }

    pub fn iri_objects(&self, subject: &str, predicate: &str) -> BTreeSet<&str> {
        let mut values: BTreeSet<&str> = self
            .inferred_facts
            .iter()
            .filter_map(|fact| {
                (fact.subject == subject && fact.predicate == predicate)
                    .then(|| fact.object.as_iri())
                    .flatten()
            })
            .collect();
        values.extend(self.asserted_data_quads.iter().filter_map(|quad| {
            if quad.subject == subject && quad.predicate == predicate {
                if let ExactTerm::Iri(object) = &quad.object {
                    return Some(object.as_str());
                }
            }
            None
        }));
        values
    }

    /// Freeze the portable identity consumed by engine/service adapters. The
    /// prepared object itself retains only local lookup data, never source or
    /// sandbox handles.
    pub fn descriptor(
        &self,
        capture: SnapshotRef,
        manifest: &AuthorizedViewManifest,
    ) -> Result<PreparedOntologyDescriptor> {
        Ok(PreparedOntologyDescriptor {
            capture,
            authorized_premise_root: manifest.authorized_premise_root.0.clone(),
            execution_manifest_root: manifest.execution_manifest_root.0.clone(),
            ontology_profile: VersionId::new(manifest.ontology_profile.identity.clone())?,
            full_ontology_bundle_root: manifest.ontology_profile.full_bundle_root.clone(),
            ontology_profile_result_root: manifest.ontology_profile.result_root.clone(),
            reasoner_input_root: manifest.reasoner_input_root.clone(),
            structural_mapping_algorithm: VersionId::new(
                manifest.structural_mapping_algorithm.clone(),
            )?,
            profile_limits_identity: manifest.profile_limits_identity.clone(),
            materialization_limits_identity: self.materialization_limits_identity.clone(),
            reasoning_limits_identity: self.reasoning_limits_identity.clone(),
            budget_identity: self.budget_identity.clone(),
            prepared_root: self.prepared_root.clone(),
            materializer: VersionId::new(match manifest.ontology_profile.identity.as_str() {
                ONTOLOGY_PROFILE_V2_ID => "ctxql-fluree-authorized-union/v2",
                ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID => {
                    "ctxql-fluree-authorized-union/v3-supported-subset"
                }
                CURRENT_REASONING_PROFILE_ID => {
                    "ctxql-fluree-authorized-union/current-4.2.1-supported-reasoning/v1"
                }
                _ => "ctxql-fluree-authorized-union/v1",
            })?,
            reasoner: VersionId::new(format!(
                "{}{}",
                crate::backend_identity::REASONER_PREFIX,
                manifest.ontology_profile.identity
            ))?,
            diagnostics_root: self.diagnostics_root.clone(),
            completeness_root: ContentHash::of_bytes(manifest.protected_completeness.as_bytes()),
        })
    }
}

pub async fn reason_authorized_manifest(
    manifest: &AuthorizedViewManifest,
    limits: SandboxLimits,
) -> Result<PreparedOntology> {
    // The v2/v3 executable profiles are immutable parity evidence for the
    // historical 603974f backend. Decoding that evidence is supported, but the
    // 4.2.1 executor must not run while claiming those semantics.
    if manifest
        .ontology_profile
        .identity
        .contains("603974fad5c13efed9d147d214d613849fb43c73")
    {
        return Err(Error::new(
            ErrorKind::Unsupported,
            crate::backend_identity::HISTORICAL_EXECUTOR_UNAVAILABLE,
        ));
    }
    manifest.validate().map_err(|reason| {
        if reason == "ontology_profile_unsupported" {
            Error::new(ErrorKind::Unsupported, reason)
        } else {
            Error::invalid(reason)
        }
    })?;
    match manifest.ontology_profile.identity.as_str() {
        ONTOLOGY_PROFILE_V2_ID | CURRENT_REASONING_PROFILE_ID => {
            let profile_limits = OntologyProfileLimits::default();
            let classified =
                if manifest.ontology_profile.identity == CURRENT_REASONING_PROFILE_ID {
                    classify_current_reasoning_profile(&manifest.schema_quads, profile_limits)
                } else {
                    classify_ontology_bundle_v2(&manifest.schema_quads, profile_limits)
                }
                .map_err(|reason| {
                    if reason == "ontology_profile_unsupported" {
                        Error::new(ErrorKind::Unsupported, reason)
                    } else {
                        Error::invalid(reason)
                    }
                })?;
            let expected_input = build_reasoner_input(
                &manifest.capture,
                &manifest.data_quads,
                &classified.reasoner_projection.quads,
            )
            .map_err(Error::invalid)?;
            if classified.full_bundle_root != manifest.ontology_profile.full_bundle_root
                || classified.result_root != manifest.ontology_profile.result_root
                || classified.limits_identity != manifest.profile_limits_identity
                || expected_input != manifest.reasoner_input_quads
                || quad_root(&expected_input) != manifest.reasoner_input_root
            {
                return Err(Error::invalid("authorized_manifest_invalid"));
            }
        }
        ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID => {
            let supported = manifest
                .supported_subset
                .as_ref()
                .ok_or_else(|| Error::invalid("authorized_manifest_invalid"))?;
            if supported.input().profile_limits_identity != manifest.profile_limits_identity
                || quad_root(&manifest.reasoner_input_quads) != manifest.reasoner_input_root
            {
                return Err(Error::invalid("authorized_manifest_invalid"));
            }
        }
        crate::ontology_profile::ONTOLOGY_PROFILE_ID => {
            let classified =
                classify_ontology_bundle(&manifest.schema_quads).map_err(|reason| {
                    if reason == "ontology_profile_unsupported" {
                        Error::new(ErrorKind::Unsupported, reason)
                    } else {
                        Error::invalid(reason)
                    }
                })?;
            if classified.supported != manifest.schema_quads || !classified.harmless.is_empty() {
                return Err(Error::invalid("authorized_manifest_invalid"));
            }
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ontology_profile_unsupported",
            ))
        }
    }
    let facts = manifest.reasoner_input_quads.len();
    if facts > limits.max_input_facts {
        return Err(Error::limit());
    }
    let trig = materialization_trig(manifest, limits.max_input_bytes)?;
    let prepared = tokio::time::timeout(
        limits.materialization_timeout,
        materialize_and_reason(manifest, trig, &limits),
    )
    .await
    .map_err(|_| Error::new(ErrorKind::Deadline, "sandbox_materialization_timeout"))??;
    Ok(prepared)
}

fn materialization_trig(manifest: &AuthorizedViewManifest, max_bytes: usize) -> Result<String> {
    const UNION: &str = "urn:ctxql:sandbox-union";
    let mut trig = String::new();
    let mut by_graph: BTreeMap<&str, Vec<&SourceQuad>> = BTreeMap::new();
    for quad in &manifest.reasoner_input_quads {
        validate_quad(quad)?;
        validate_iri(&quad.graph)?;
        by_graph.entry(&quad.graph).or_default().push(quad);
    }
    if let Some(quads) = by_graph.remove(UNION) {
        for quad in quads {
            trig.push_str(&quad.turtle());
            trig.push('\n');
            if trig.len() > max_bytes {
                return Err(Error::limit());
            }
        }
    }
    for (graph, quads) in by_graph {
        trig.push_str(&format!("GRAPH <{graph}> {{\n"));
        for quad in quads {
            trig.push_str(&quad.turtle());
            trig.push('\n');
        }
        trig.push_str("}\n");
        if trig.len() > max_bytes {
            return Err(Error::limit());
        }
    }
    Ok(trig)
}

fn validate_quad(quad: &SourceQuad) -> Result<()> {
    let subject = quad
        .subject_iri()
        .ok_or_else(|| Error::invalid("reasoner_input_divergence"))?;
    validate_iri(subject)?;
    validate_iri(&quad.predicate)?;
    match &quad.object {
        ExactTerm::Iri(iri) => validate_iri(iri)?,
        ExactTerm::ScopedBlankNode(_) => return Err(Error::invalid("reasoner_input_divergence")),
        ExactTerm::Literal { .. } => {}
    }
    Ok(())
}

fn validate_iri(iri: &str) -> Result<()> {
    if iri.starts_with("_:") || !iri.contains(':') {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "blank_node_not_supported",
        ));
    }
    Ok(())
}

async fn materialize_and_reason(
    manifest: &AuthorizedViewManifest,
    trig: String,
    limits: &SandboxLimits,
) -> Result<PreparedOntology> {
    // Keep the native owner off the bounded Tokio/test thread stack. Fluree's
    // ledger state is large enough that combining it with the reasoner future
    // in one stack frame can overflow the default test-thread stack.
    let mut sandbox = Box::new(SandboxScope::new());
    let sandbox_id = SANDBOX_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let sandbox_ledger = format!("ctxql/p5-5-authorized-sandbox-{sandbox_id}:main");
    let materialization = sandbox
        .fluree()
        .stage_owned(genesis(&sandbox_ledger))
        .upsert_turtle(&trig)
        .execute();
    let ledger = Box::pin(materialization)
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "sandbox_materialization_failed"))?
        .ledger;
    sandbox.install_ledger(ledger);
    let ledger = sandbox.ledger();
    Box::pin(verify_readback(ledger, manifest)).await?;

    let schema_flakes = if matches!(
        manifest.ontology_profile.identity.as_str(),
        ONTOLOGY_PROFILE_V2_ID
            | ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID
            | CURRENT_REASONING_PROFILE_ID
    ) {
        // E0 already sealed the complete, authorized, graph-flattened reasoner input.
        // C0 composes only that materialized input and accepts no source,
        // configuration, import, schema, or policy side channel.
        Arc::new(SchemaBundleFlakes::empty())
    } else {
        // Historical P5.5 manifests retained schema graph identity in their
        // sandbox input and therefore still require Fluree's schema overlay.
        let reasoning = fluree_db_core::ledger_config::ReasoningDefaults {
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
        };
        let bundle = Box::pin(ontology_imports::resolve_schema_bundle(
            &ledger.snapshot,
            ledger.novelty.as_ref(),
            ledger.t(),
            &reasoning,
        ))
        .await
        .map_err(|_| Error::invalid("ontology_configuration_invalid"))?
        .ok_or_else(|| Error::invalid("ontology_configuration_invalid"))?;
        Box::pin(ontology_imports::get_or_build_schema_bundle_flakes(
            &ledger.snapshot,
            ledger.novelty.as_ref(),
            &bundle,
        ))
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "ontology_schema_bundle_failed"))?
    };
    let overlay = SchemaBundleOverlay::new(ledger.novelty.as_ref(), schema_flakes);
    let hierarchy = Box::pin(compute_schema_hierarchy_with_overlay(
        &ledger.snapshot,
        &overlay,
        ledger.t(),
    ))
    .await
    .map_err(|_| Error::new(ErrorKind::Backend, "ontology_schema_hierarchy_failed"))?
    .unwrap_or_else(|| SchemaHierarchy::from_db_root_schema(&IndexSchema::default()));
    let (class_entailments, property_entailments) =
        hierarchy_entailments(&ledger.snapshot, &hierarchy, manifest);
    let reasoning_options = ReasoningOptions::with_budget(limits.reasoning.clone());
    let reasoning_cache = ReasoningCache::new(1);
    let result = Box::pin(reason_owl2rl(
        GraphDbRef::new(&ledger.snapshot, 0, &overlay, ledger.t()),
        &reasoning_options,
        &reasoning_cache,
    ))
    .await
    .map_err(|_| Error::new(ErrorKind::Backend, "ontology_reasoning_failed"))?;
    let diagnostics = normalize(&result);
    if diagnostics.capped {
        return Err(Error::new(
            ErrorKind::Limit,
            "ontology_reasoning_incomplete",
        ));
    }
    let diagnostics_identity = diagnostics_commitment(&diagnostics);
    let diagnostics_root = ContentHash::of_bytes(diagnostics_identity.as_bytes());
    let mut inferred_facts = hierarchy_facts(
        &manifest.data_quads,
        &class_entailments,
        &property_entailments,
    );
    inferred_facts.extend(normalize_reasoning_overlay(&ledger.snapshot, &result)?);
    let inferred_iri_triples = inferred_facts
        .iter()
        .filter_map(|fact| {
            fact.object.as_iri().map(|object| {
                (
                    fact.subject.clone(),
                    fact.predicate.clone(),
                    object.to_owned(),
                )
            })
        })
        .collect();
    let asserted_root = quad_root(&manifest.data_quads);
    let inferred_root = prepared_fact_root(&inferred_facts);
    let budget_identity = ContentHash::of_bytes(limits.budget_identity.as_bytes());
    let materialization_limits_identity = ContentHash::of_bytes(
        format!(
            "ctxql-materialization-limits/v2;facts={};bytes={};timeout_ms={}",
            limits.max_input_facts,
            limits.max_input_bytes,
            limits.materialization_timeout.as_millis()
        )
        .as_bytes(),
    );
    let reasoning_limits_identity = ContentHash::of_bytes(
        format!("ctxql-reasoning-limits/v2;{}", limits.budget_identity).as_bytes(),
    );
    let prepared_root = if manifest.ontology_profile.identity == ONTOLOGY_PROFILE_V2_ID
        || manifest.ontology_profile.identity == CURRENT_REASONING_PROFILE_ID
    {
        framed_root(
            if manifest.ontology_profile.identity == CURRENT_REASONING_PROFILE_ID {
                "ctxql-prepared-ontology/current-4.2.1-supported-reasoning/v1"
            } else {
                "ctxql-prepared-ontology/v2"
            },
            [
                (
                    "execution-manifest",
                    manifest.execution_manifest_root.0.as_str(),
                ),
                ("materializer", "ctxql-fluree-authorized-union/v2"),
                (
                    "reasoner-profile",
                    manifest.ontology_profile.identity.as_str(),
                ),
                (
                    "profile-result",
                    manifest.ontology_profile.result_root.as_str(),
                ),
                ("reasoner-input", manifest.reasoner_input_root.as_str()),
                ("asserted", asserted_root.as_str()),
                ("inferred", inferred_root.as_str()),
                ("budget", budget_identity.as_str()),
                (
                    "materialization-limits",
                    materialization_limits_identity.as_str(),
                ),
                ("reasoning-limits", reasoning_limits_identity.as_str()),
                ("diagnostics", diagnostics_identity.as_str()),
            ],
        )
    } else if manifest.ontology_profile.identity == ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID {
        framed_root(
            "ctxql-prepared-ontology/v3-supported-subset",
            [
                (
                    "execution-manifest",
                    manifest.execution_manifest_root.0.as_str(),
                ),
                (
                    "materializer",
                    "ctxql-fluree-authorized-union/v3-supported-subset",
                ),
                (
                    "reasoner-profile",
                    manifest.ontology_profile.identity.as_str(),
                ),
                (
                    "profile-result",
                    manifest.ontology_profile.result_root.as_str(),
                ),
                ("reasoner-input", manifest.reasoner_input_root.as_str()),
                ("asserted", asserted_root.as_str()),
                ("inferred", inferred_root.as_str()),
                ("budget", budget_identity.as_str()),
                (
                    "materialization-limits",
                    materialization_limits_identity.as_str(),
                ),
                ("reasoning-limits", reasoning_limits_identity.as_str()),
                ("diagnostics", diagnostics_identity.as_str()),
            ],
        )
    } else {
        framed_root(
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
                ("budget", limits.budget_identity.as_str()),
                ("diagnostics", diagnostics_identity.as_str()),
            ],
        )
    };
    Ok(PreparedOntology {
        asserted_data_quads: manifest.data_quads.clone(),
        inferred_facts,
        inferred_iri_triples,
        class_entailments,
        property_entailments,
        diagnostics,
        diagnostics_root,
        prepared_root,
        budget_identity,
        materialization_limits_identity,
        reasoning_limits_identity,
    })
}

/// Normalizes native inferred overlay facts through the same exact-term and
/// structural-identity boundary used by production C0 readback.
#[doc(hidden)]
pub fn normalize_reasoning_overlay(
    snapshot: &LedgerSnapshot,
    result: &fluree_db_reasoner::ReasoningResult,
) -> Result<BTreeSet<PreparedFact>> {
    let mut facts = BTreeSet::new();
    for flake in result.overlay.flakes_spot() {
        let subject = snapshot
            .decode_sid(&flake.s)
            .ok_or_else(|| Error::new(ErrorKind::Backend, "exact_inferred_decode_failed"))?;
        let predicate = snapshot
            .decode_sid(&flake.p)
            .ok_or_else(|| Error::new(ErrorKind::Backend, "exact_inferred_decode_failed"))?;
        if is_internal_structural_iri(&subject) || is_internal_structural_iri(&predicate) {
            continue;
        }
        let object = decode_flake_object(
            snapshot,
            &flake.o,
            &flake.dt,
            flake.m.as_ref(),
            false,
            "exact_inferred_decode_failed",
        )
        .map_err(|reason| Error::new(ErrorKind::Backend, reason))?;
        if object.as_iri().is_some_and(is_internal_structural_iri) {
            continue;
        }
        facts.insert(PreparedFact {
            subject,
            predicate,
            object,
        });
    }
    Ok(facts)
}

type EntailmentPairs = BTreeSet<(String, String)>;

fn hierarchy_facts(
    data_quads: &BTreeSet<SourceQuad>,
    class_entailments: &EntailmentPairs,
    property_entailments: &EntailmentPairs,
) -> BTreeSet<PreparedFact> {
    const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
    let mut facts = BTreeSet::new();
    for quad in data_quads {
        let Some(subject) = quad.subject.as_iri() else {
            continue;
        };
        for (_, target) in property_entailments
            .range((quad.predicate.clone(), String::new())..)
            .take_while(|(actual, _)| actual == &quad.predicate)
        {
            facts.insert(PreparedFact {
                subject: subject.to_owned(),
                predicate: target.clone(),
                object: quad.object.clone(),
            });
        }
        if quad.predicate == RDF_TYPE {
            if let Some(actual) = quad.object.as_iri() {
                for (_, target) in class_entailments
                    .range((actual.to_owned(), String::new())..)
                    .take_while(|(descendant, _)| descendant == actual)
                {
                    facts.insert(PreparedFact {
                        subject: subject.to_owned(),
                        predicate: RDF_TYPE.into(),
                        object: ExactTerm::Iri(target.clone()),
                    });
                }
            }
        }
    }
    facts
}

fn hierarchy_entailments(
    snapshot: &LedgerSnapshot,
    hierarchy: &fluree_db_core::SchemaHierarchy,
    manifest: &AuthorizedViewManifest,
) -> (EntailmentPairs, EntailmentPairs) {
    const SUBCLASS: &str = "http://www.w3.org/2000/01/rdf-schema#subClassOf";
    const SUBPROPERTY: &str = "http://www.w3.org/2000/01/rdf-schema#subPropertyOf";
    let mut classes = BTreeSet::new();
    let mut properties = BTreeSet::new();
    for quad in &manifest.schema_quads {
        let ExactTerm::Iri(target) = &quad.object else {
            continue;
        };
        let Some(target_sid) = snapshot.encode_iri(target) else {
            continue;
        };
        let (destination, descendants) = if quad.predicate == SUBCLASS {
            (&mut classes, hierarchy.subclasses_of(&target_sid))
        } else if quad.predicate == SUBPROPERTY {
            (&mut properties, hierarchy.subproperties_of(&target_sid))
        } else {
            continue;
        };
        for descendant in descendants {
            if let Some(actual) = snapshot.decode_sid(descendant) {
                destination.insert((actual, target.clone()));
            }
        }
    }
    (classes, properties)
}

fn normalize(result: &fluree_db_reasoner::ReasoningResult) -> NormalizedDiagnostics {
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

fn is_internal_structural_iri(value: &str) -> bool {
    value.starts_with(STRUCTURAL_NODE_IRI_PREFIX)
}

fn prepared_fact_root(facts: &BTreeSet<PreparedFact>) -> ContentHash {
    let mut bytes = Vec::new();
    for fact in facts {
        let commitment = format!(
            "S{}:{}P{}:{}O{}",
            fact.subject.len(),
            fact.subject,
            fact.predicate.len(),
            fact.predicate,
            fact.object.commitment()
        );
        bytes.extend_from_slice(commitment.len().to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(commitment.as_bytes());
    }
    ContentHash::of_bytes(&bytes)
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

async fn verify_readback(ledger: &LedgerState, manifest: &AuthorizedViewManifest) -> Result<()> {
    const UNION: &str = "urn:ctxql:sandbox-union";
    let actual_union = read_graph_quads(ledger, 0, UNION).await?;
    let expected_union = manifest
        .reasoner_input_quads
        .iter()
        .filter(|quad| quad.graph == UNION)
        .cloned()
        .collect();
    if actual_union != expected_union {
        return Err(Error::new(
            ErrorKind::Backend,
            "sandbox_materialization_mismatch",
        ));
    }
    let graphs = manifest
        .reasoner_input_quads
        .iter()
        .filter(|quad| quad.graph != UNION)
        .map(|quad| quad.graph.as_str())
        .collect::<BTreeSet<_>>();
    for graph in graphs {
        let graph_id = ledger
            .snapshot
            .graph_registry
            .graph_id_for_iri(graph)
            .ok_or_else(|| Error::new(ErrorKind::Backend, "sandbox_materialization_mismatch"))?;
        let actual = read_graph_quads(ledger, graph_id, graph).await?;
        let expected = manifest
            .reasoner_input_quads
            .iter()
            .filter(|quad| quad.graph == graph)
            .cloned()
            .collect();
        if actual != expected {
            return Err(Error::new(
                ErrorKind::Backend,
                "sandbox_materialization_mismatch",
            ));
        }
    }
    Ok(())
}

async fn read_graph_quads(
    ledger: &LedgerState,
    graph_id: u16,
    graph_label: &str,
) -> Result<BTreeSet<SourceQuad>> {
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
    .map_err(|_| Error::new(ErrorKind::Backend, "exact_materialization_read_failed"))?;
    let mut quads = BTreeSet::new();
    for batch in batches {
        for row in 0..batch.len() {
            let subject_binding = batch.get(row, subject).ok_or_else(|| {
                Error::new(ErrorKind::Backend, "exact_materialization_decode_failed")
            })?;
            let predicate_binding = batch.get(row, predicate).ok_or_else(|| {
                Error::new(ErrorKind::Backend, "exact_materialization_decode_failed")
            })?;
            let object_binding = batch.get(row, object).ok_or_else(|| {
                Error::new(ErrorKind::Backend, "exact_materialization_decode_failed")
            })?;
            let object = decode_exact_term(
                &ledger.snapshot,
                object_binding,
                false,
                "exact_materialization_decode_failed",
            )
            .map_err(|reason| Error::new(ErrorKind::Backend, reason))?;
            quads.insert(SourceQuad {
                graph: graph_label.into(),
                subject: decode_node(
                    &ledger.snapshot,
                    subject_binding,
                    "exact_materialization_decode_failed",
                )
                .map_err(|reason| Error::new(ErrorKind::Backend, reason))?,
                predicate: decode_exact_iri(
                    &ledger.snapshot,
                    predicate_binding,
                    "exact_materialization_decode_failed",
                )
                .map_err(|reason| Error::new(ErrorKind::Backend, reason))?,
                object,
            });
        }
    }
    Ok(quads)
}

fn genesis(ledger: &str) -> LedgerState {
    LedgerState::new(LedgerSnapshot::genesis(ledger), Novelty::new(0))
}

#[cfg(test)]
mod teardown_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    fn finish_with(probe: Arc<AtomicUsize>, result: Result<()>) -> Result<()> {
        let mut sandbox = SandboxScope::with_teardown_probe(probe);
        sandbox.install_ledger(genesis("teardown-test:main"));
        result
    }

    #[tokio::test]
    async fn one_scope_tears_down_once_on_success_error_and_cap() {
        for result in [
            Ok(()),
            Err(Error::new(ErrorKind::Backend, "test_error")),
            Err(Error::new(ErrorKind::Limit, "test_cap")),
        ] {
            let probe = Arc::new(AtomicUsize::new(0));
            let _ = finish_with(Arc::clone(&probe), result);
            assert_eq!(probe.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn timeout_drops_the_owned_sandbox_scope() {
        let probe = Arc::new(AtomicUsize::new(0));
        let inner_probe = Arc::clone(&probe);
        let result = tokio::time::timeout(Duration::from_millis(1), async move {
            let mut sandbox = SandboxScope::with_teardown_probe(inner_probe);
            sandbox.install_ledger(genesis("timeout-test:main"));
            std::future::pending::<()>().await;
        })
        .await;
        assert!(result.is_err());
        assert_eq!(probe.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn caller_cancellation_drops_the_owned_sandbox_scope() {
        let probe = Arc::new(AtomicUsize::new(0));
        let inner_probe = Arc::clone(&probe);
        {
            let operation = async move {
                let mut sandbox = SandboxScope::with_teardown_probe(inner_probe);
                sandbox.install_ledger(genesis("cancellation-test:main"));
                std::future::pending::<()>().await;
            };
            tokio::pin!(operation);
            tokio::select! {
                biased;
                _ = &mut operation => unreachable!("sandbox operation is pending"),
                _ = std::future::ready(()) => {}
            }
        }
        assert_eq!(probe.load(Ordering::SeqCst), 1);
    }
}
