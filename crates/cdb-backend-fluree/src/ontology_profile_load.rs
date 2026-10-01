//! Bounded, one-transaction POC loader for a certified ontology profile.
//!
//! This module is intentionally a bootstrap/proof utility rather than a
//! production writer. It creates a fresh file ledger, inserts the complete
//! named-graph image and v3 activation in one native JSON-LD transaction, then
//! returns the exact committed `(ledger, t, CID)` and structural mapping root.

use crate::{
    authorized_view::{ExactTerm, RdfNodeId, SourceQuad},
    ontology_profile_v3::CertifiedOntologyProfileV3,
};
use cdb_core::{id::ContentHash, Limits};
use fluree_db_api::{FlureeBuilder, NameServiceMode};
use fluree_db_nameservice::file::FileNameService;
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};

pub const ONTOLOGY_PROFILE_PREDICATE: &str =
    "https://ctxql.example/semantic-rdf/v2/ontologyProfile";
pub const CONSTRUCT_AUDIT_ROOT_PREDICATE: &str =
    "https://ctxql.example/semantic-rdf/v2/constructAuditRoot";
pub const EXECUTABLE_PROFILE_ROOT_PREDICATE: &str =
    "https://ctxql.example/semantic-rdf/v2/executableProfileRoot";
pub const EXECUTABLE_PROFILE_MANIFEST_PREDICATE: &str =
    "https://ctxql.example/semantic-rdf/v2/executableProfileManifest";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const XSD_BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";
const RDF_LANG_STRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";
const F: &str = "https://ns.flur.ee/db#";
const CTXQL: &str = "https://ctxql.example/semantic-rdf/v1/";

pub type LoadResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OntologyProfileLoadLimits {
    pub max_quads: usize,
    pub max_transaction_bytes: usize,
    pub max_structural_nodes: usize,
}

impl Default for OntologyProfileLoadLimits {
    fn default() -> Self {
        Self {
            max_quads: 500_000,
            max_transaction_bytes: 4 * 1024 * 1024,
            max_structural_nodes: 200_000,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LoadNode {
    Iri(String),
    Blank(String),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LoadTerm {
    Iri(String),
    Blank(String),
    Literal {
        lexical: String,
        datatype: String,
        language: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LoadQuad {
    pub graph: String,
    pub subject: LoadNode,
    pub predicate: String,
    pub object: LoadTerm,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OntologyProfileLoadPlan {
    pub ledger: String,
    pub source_closure: BTreeSet<SourceQuad>,
    pub config_graph: String,
    pub config_subject: String,
    pub certified_profile: CertifiedOntologyProfileV3,
    pub limits: OntologyProfileLoadLimits,
}

/// Experimental source-only load. Unlike [`OntologyProfileLoadPlan`], this
/// deliberately carries no profile marker or Fluree configuration assertions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawOntologyLoadPlan {
    pub ledger: String,
    pub source_quads: BTreeSet<SourceQuad>,
    pub limits: OntologyProfileLoadLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OntologyProfileLoadReceipt {
    pub ledger: String,
    pub t: i64,
    pub cid: String,
    pub ontology_quad_count: usize,
    pub transaction_quad_count: usize,
    pub transaction_bytes: usize,
    pub structural_node_count: usize,
    pub structural_mapping_root: ContentHash,
}

fn load_quads_from_source(quads: &BTreeSet<SourceQuad>) -> Vec<LoadQuad> {
    quads
        .iter()
        .map(|quad| LoadQuad {
            graph: quad.graph.clone(),
            subject: match &quad.subject {
                RdfNodeId::Iri(value) => LoadNode::Iri(value.clone()),
                RdfNodeId::ScopedBlankNode(value) => LoadNode::Blank(value.clone()),
            },
            predicate: quad.predicate.clone(),
            object: match &quad.object {
                ExactTerm::Iri(value) => LoadTerm::Iri(value.clone()),
                ExactTerm::ScopedBlankNode(value) => LoadTerm::Blank(value.clone()),
                ExactTerm::Literal {
                    lexical,
                    datatype,
                    language,
                } => LoadTerm::Literal {
                    lexical: lexical.clone(),
                    datatype: datatype.clone(),
                    language: language.clone(),
                },
            },
        })
        .collect()
}

/// Create a fresh file ledger and commit the whole profile in one transaction.
/// `create_ledger` establishes the empty ledger; every profile/configuration
/// assertion is contained in the single following native transaction.
pub async fn load_file_once(
    path: impl AsRef<Path>,
    plan: OntologyProfileLoadPlan,
) -> LoadResult<OntologyProfileLoadReceipt> {
    load_file_once_internal(path, plan, None).await
}

/// Create a fresh certified ledger with an explicit acquisition-review graph
/// role in the same initial transaction. Historical loaders remain byte-for-byte
/// compatible through [`load_file_once`].
pub async fn load_file_once_with_review_graph(
    path: impl AsRef<Path>,
    plan: OntologyProfileLoadPlan,
    review_graph: &str,
) -> LoadResult<OntologyProfileLoadReceipt> {
    validate_iri(review_graph)?;
    load_file_once_internal(path, plan, Some(review_graph)).await
}

async fn load_file_once_internal(
    path: impl AsRef<Path>,
    plan: OntologyProfileLoadPlan,
    review_graph: Option<&str>,
) -> LoadResult<OntologyProfileLoadReceipt> {
    // Certification and exact source closure are checked before constructing a
    // transaction or opening a writer. The certified manifest already binds
    // the audit, category/count/occurrence/source-entry, component, registry,
    // family, annotation, caveat, C0, limits, dependency, and final Gate-3
    // coverage commitments verified by `certify_ontology_profile_v3`.
    if !plan.certified_profile.verify_integrity() {
        return Err("ontology profile certification invalid".into());
    }
    if plan.source_closure != plan.certified_profile.analysis().full_bundle {
        return Err("ontology profile certified source closure mismatch".into());
    }

    validate_iri(&plan.ledger)?;
    validate_iri(&plan.config_graph)?;
    validate_iri(&plan.config_subject)?;
    if plan.source_closure.is_empty() || plan.source_closure.len() > plan.limits.max_quads {
        return Err("ontology profile load quad limit exceeded".into());
    }
    let manifest = plan.certified_profile.manifest();
    let manifest_bytes = manifest.canonical_bytes(Limits::default())?;
    let manifest_literal = std::str::from_utf8(&manifest_bytes)?;
    let executable_profile_root = manifest.root(Limits::default())?;
    let selected_scope = manifest.input().selected_scope.clone();

    let expected_config_graph = fluree_db_core::graph_registry::config_graph_iri(&plan.ledger);
    if plan.config_graph != expected_config_graph {
        return Err("ontology profile configuration graph mismatch".into());
    }
    let ontology_quad_count = plan.source_closure.len();
    let mut quads = load_quads_from_source(&plan.source_closure);
    let support = poc_support_quads(
        &plan.ledger,
        &plan.config_graph,
        &plan.config_subject,
        &selected_scope,
        &quads,
    )?;
    quads.extend(support);
    if let Some(review_graph) = review_graph {
        let claim_graph = format!("urn:ctxql:p5-7:{}:claims", plan.ledger);
        let data_graph = format!("urn:ctxql:p5-7:{}:data", plan.ledger);
        if review_graph == plan.config_graph
            || review_graph == claim_graph
            || review_graph == data_graph
            || plan
                .source_closure
                .iter()
                .any(|quad| quad.graph == review_graph)
        {
            return Err("ontology profile review graph role overlap".into());
        }
        quads.push(LoadQuad {
            graph: plan.config_graph.clone(),
            subject: LoadNode::Iri(plan.config_subject.clone()),
            predicate: "https://ctxql.example/semantic-rdf/v1/reviewGraph".into(),
            object: LoadTerm::Iri(review_graph.to_owned()),
        });
    }
    for (predicate, lexical) in [
        (
            ONTOLOGY_PROFILE_PREDICATE,
            plan.certified_profile.identity().to_owned(),
        ),
        (
            CONSTRUCT_AUDIT_ROOT_PREDICATE,
            manifest.input().construct_audit_root.as_str().to_owned(),
        ),
        (
            EXECUTABLE_PROFILE_ROOT_PREDICATE,
            executable_profile_root.as_str().to_owned(),
        ),
        (
            EXECUTABLE_PROFILE_MANIFEST_PREDICATE,
            manifest_literal.to_owned(),
        ),
    ] {
        quads.push(LoadQuad {
            graph: plan.config_graph.clone(),
            subject: LoadNode::Iri(plan.config_subject.clone()),
            predicate: predicate.to_owned(),
            object: LoadTerm::Literal {
                lexical,
                datatype: XSD_STRING.to_owned(),
                language: None,
            },
        });
    }
    if quads.len() > plan.limits.max_quads {
        return Err("ontology profile load quad limit exceeded".into());
    }

    let (transaction, mapping_root, structural_node_count) =
        native_transaction(&quads, plan.limits.max_structural_nodes)?;
    let transaction_bytes = serde_json::to_vec(&transaction)?.len();
    if transaction_bytes > plan.limits.max_transaction_bytes {
        return Err("ontology profile load transaction limit exceeded".into());
    }

    let path = path.as_ref().to_string_lossy().into_owned();
    let writer = FlureeBuilder::file(path).without_indexing().build()?;
    let ledger = writer.create_ledger(&plan.ledger).await?;
    let committed = writer.insert(ledger, &transaction).await?.ledger;
    let t = committed.t();
    let cid = committed
        .head_commit_id
        .as_ref()
        .ok_or("ontology profile load missing commit CID")?
        .to_string();
    if t != 1 {
        return Err("ontology profile load was not one transaction".into());
    }

    Ok(OntologyProfileLoadReceipt {
        ledger: plan.ledger,
        t,
        cid,
        ontology_quad_count,
        transaction_quad_count: quads.len(),
        transaction_bytes,
        structural_node_count,
        structural_mapping_root: mapping_root,
    })
}

/// Reconstruct the loader's graph-scoped source-label mapping commitment
/// without opening a ledger. This is metadata about the transaction mapping;
/// loaded-content integrity is checked separately under structural relabeling.
pub fn raw_structural_mapping_commitment(
    source_quads: &BTreeSet<SourceQuad>,
    max_structural_nodes: usize,
) -> LoadResult<(ContentHash, usize)> {
    let quads = load_quads_from_source(source_quads);
    let (_, root, count) = native_transaction(&quads, max_structural_nodes)?;
    Ok((root, count))
}

/// Create a fresh file ledger containing only source quads in one bounded
/// native transaction. No profile, configuration, schema-source, policy, or
/// claim assertions are added.
pub async fn load_raw_file_once(
    path: impl AsRef<Path>,
    plan: RawOntologyLoadPlan,
) -> LoadResult<OntologyProfileLoadReceipt> {
    validate_iri(&plan.ledger)?;
    if plan.source_quads.is_empty() || plan.source_quads.len() > plan.limits.max_quads {
        return Err("raw ontology load quad limit exceeded".into());
    }
    let ontology_quad_count = plan.source_quads.len();
    let quads = load_quads_from_source(&plan.source_quads);
    let (transaction, mapping_root, structural_node_count) =
        native_transaction(&quads, plan.limits.max_structural_nodes)?;
    let transaction_bytes = serde_json::to_vec(&transaction)?.len();
    if transaction_bytes > plan.limits.max_transaction_bytes {
        return Err("raw ontology load transaction limit exceeded".into());
    }

    let path = path.as_ref().to_string_lossy().into_owned();
    let writer = FlureeBuilder::file(path).without_indexing().build()?;
    let ledger = writer.create_ledger(&plan.ledger).await?;
    let committed = writer.insert(ledger, &transaction).await?.ledger;
    let t = committed.t();
    let cid = committed
        .head_commit_id
        .as_ref()
        .ok_or("raw ontology load missing commit CID")?
        .to_string();
    if t != 1 {
        return Err("raw ontology load was not one transaction".into());
    }

    Ok(OntologyProfileLoadReceipt {
        ledger: plan.ledger,
        t,
        cid,
        ontology_quad_count,
        transaction_quad_count: quads.len(),
        transaction_bytes,
        structural_node_count,
        structural_mapping_root: mapping_root,
    })
}

/// Reopen through a structurally read-only nameservice and prove the exact
/// receipt still names both the head and the reconstructable historical view.
pub async fn verify_read_only_reopen(
    path: impl AsRef<Path>,
    receipt: &OntologyProfileLoadReceipt,
) -> LoadResult<()> {
    let nameservice = NameServiceMode::ReadOnly(Arc::new(FileNameService::new(path.as_ref())));
    let reader = FlureeBuilder::file(path.as_ref().to_string_lossy().into_owned())
        .without_indexing()
        .build_client_with_nameservice(nameservice)
        .await?;
    let head = reader.ledger(&receipt.ledger).await?;
    if head.t() != receipt.t
        || head
            .head_commit_id
            .as_ref()
            .map(ToString::to_string)
            .as_deref()
            != Some(receipt.cid.as_str())
    {
        return Err("ontology profile reopened head mismatch".into());
    }
    let detail = reader
        .graph(&receipt.ledger)
        .commit_t(receipt.t)
        .execute()
        .await?;
    if detail.id != receipt.cid || detail.t != receipt.t {
        return Err("ontology profile reopened commit mismatch".into());
    }
    let historical = reader.ledger_view_at(&receipt.ledger, receipt.t).await?;
    if historical.to_t() != receipt.t {
        return Err("ontology profile historical view mismatch".into());
    }
    Ok(())
}

fn poc_support_quads(
    ledger: &str,
    config_graph: &str,
    config_subject: &str,
    selected_scope: &str,
    ontology_quads: &[LoadQuad],
) -> LoadResult<Vec<LoadQuad>> {
    let config = config_subject;
    let reasoning = format!("urn:ctxql:p5-7:{ledger}:reasoning");
    let schema_ref = format!("urn:ctxql:p5-7:{ledger}:schema-ref");
    let schema_source = format!("urn:ctxql:p5-7:{ledger}:schema-source");
    let policy_defaults = format!("urn:ctxql:p5-7:{ledger}:policy-defaults");
    let policy_ref = format!("urn:ctxql:p5-7:{ledger}:policy-ref");
    let policy_source = format!("urn:ctxql:p5-7:{ledger}:policy-source");
    let policy_graph = format!("urn:ctxql:p5-7:{ledger}:policy");
    let claim_graph = format!("urn:ctxql:p5-7:{ledger}:claims");
    let data_graph = format!("urn:ctxql:p5-7:{ledger}:data");
    let subject = format!("urn:ctxql:p5-7:{ledger}:subject");
    let object = format!("urn:ctxql:p5-7:{ledger}:object");
    let predicate = format!("urn:ctxql:p5-7:{ledger}:predicate");
    let policy_class = format!("urn:ctxql:p5-7:{ledger}:Policy");
    let principal = "did:example:p5-7";
    let expected_entry = format!("https://spec.edmcouncil.org/fibo/ontology/{selected_scope}/");
    let graphs = ontology_quads
        .iter()
        .map(|quad| quad.graph.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let entry_graph = if graphs.contains(&expected_entry) {
        expected_entry
    } else {
        graphs
            .iter()
            .next()
            .cloned()
            .ok_or("ontology profile has no graph")?
    };

    let iri = |graph: &str, subject: &str, predicate: &str, object: &str| LoadQuad {
        graph: graph.into(),
        subject: LoadNode::Iri(subject.into()),
        predicate: predicate.into(),
        object: LoadTerm::Iri(object.into()),
    };
    let literal =
        |graph: &str, subject: &str, predicate: &str, lexical: &str, datatype: &str| -> LoadQuad {
            LoadQuad {
                graph: graph.into(),
                subject: LoadNode::Iri(subject.into()),
                predicate: predicate.into(),
                object: LoadTerm::Literal {
                    lexical: lexical.into(),
                    datatype: datatype.into(),
                    language: None,
                },
            }
        };
    let mut result = vec![
        iri(config_graph, config, RDF_TYPE, &format!("{F}LedgerConfig")),
        iri(
            config_graph,
            config,
            &format!("{F}reasoningDefaults"),
            &reasoning,
        ),
        iri(
            config_graph,
            config,
            &format!("{F}policyDefaults"),
            &policy_defaults,
        ),
        iri(
            config_graph,
            config,
            &format!("{CTXQL}governedDataGraph"),
            &claim_graph,
        ),
        iri(
            config_graph,
            config,
            &format!("{CTXQL}governedDataGraph"),
            &data_graph,
        ),
        iri(
            config_graph,
            config,
            &format!("{CTXQL}claimGraph"),
            &claim_graph,
        ),
        iri(
            config_graph,
            &reasoning,
            &format!("{F}reasoningModes"),
            &format!("{F}owl2rl"),
        ),
        iri(
            config_graph,
            &reasoning,
            &format!("{F}schemaSource"),
            &schema_ref,
        ),
        literal(
            config_graph,
            &reasoning,
            &format!("{F}followOwlImports"),
            "true",
            XSD_BOOLEAN,
        ),
        iri(config_graph, &schema_ref, RDF_TYPE, &format!("{F}GraphRef")),
        iri(
            config_graph,
            &schema_ref,
            &format!("{F}graphSource"),
            &schema_source,
        ),
        iri(
            config_graph,
            &schema_source,
            &format!("{F}graphSelector"),
            &entry_graph,
        ),
        literal(
            config_graph,
            &policy_defaults,
            &format!("{F}defaultAllow"),
            "true",
            XSD_BOOLEAN,
        ),
        iri(
            config_graph,
            &policy_defaults,
            &format!("{F}policySource"),
            &policy_ref,
        ),
        iri(config_graph, &policy_ref, RDF_TYPE, &format!("{F}GraphRef")),
        iri(
            config_graph,
            &policy_ref,
            &format!("{F}graphSource"),
            &policy_source,
        ),
        iri(
            config_graph,
            &policy_source,
            &format!("{F}graphSelector"),
            &policy_graph,
        ),
        iri(
            &policy_graph,
            principal,
            &format!("{F}policyClass"),
            &policy_class,
        ),
        iri(&data_graph, &subject, RDF_TYPE, "urn:ctxql:p5-7:Entity"),
        // Register a non-claim statement so the required claim graph exists while
        // the loader remains independent of Fluree's system-controlled
        // edge-annotation representation. Historical preparation sees an empty
        // claim set and still exercises the complete ontology path.
        iri(&claim_graph, &subject, &predicate, &object),
    ];
    result.extend(graphs.into_iter().map(|graph| {
        iri(
            config_graph,
            config,
            &format!("{CTXQL}infrastructureGraph"),
            &graph,
        )
    }));
    Ok(result)
}

fn native_transaction(
    quads: &[LoadQuad],
    max_structural_nodes: usize,
) -> LoadResult<(Value, ContentHash, usize)> {
    let mut structural_keys = BTreeSet::<(String, String)>::new();
    for quad in quads {
        validate_iri(&quad.graph)?;
        validate_iri(&quad.predicate)?;
        if let LoadNode::Blank(label) = &quad.subject {
            validate_blank(label)?;
            structural_keys.insert((quad.graph.clone(), label.clone()));
        } else if let LoadNode::Iri(iri) = &quad.subject {
            validate_iri(iri)?;
        }
        match &quad.object {
            LoadTerm::Iri(iri) => validate_iri(iri)?,
            LoadTerm::Blank(label) => {
                validate_blank(label)?;
                structural_keys.insert((quad.graph.clone(), label.clone()));
            }
            LoadTerm::Literal {
                lexical,
                datatype,
                language,
            } => {
                if lexical.as_bytes().contains(&0) {
                    return Err("ontology profile literal contains NUL".into());
                }
                validate_iri(datatype)?;
                if language.as_ref().is_some_and(|value| value.is_empty())
                    || (language.is_some() && datatype != RDF_LANG_STRING)
                    || (language.is_none() && datatype == RDF_LANG_STRING)
                {
                    return Err("ontology profile language tag invalid".into());
                }
            }
        }
    }
    if structural_keys.len() > max_structural_nodes {
        return Err("ontology profile structural node limit exceeded".into());
    }
    let mut label_counts = BTreeMap::<String, usize>::new();
    for (_, label) in &structural_keys {
        *label_counts.entry(label.clone()).or_default() += 1;
    }
    let structural = structural_keys
        .into_iter()
        .map(|(graph, label)| {
            let mapped = if label_counts[&label] == 1 {
                label.clone()
            } else {
                let root = ContentHash::of_bytes(format!("{graph}\0{label}").as_bytes());
                format!("_:ctxql-{}", &root.as_str()[7..])
            };
            ((graph, label), mapped)
        })
        .collect::<BTreeMap<_, _>>();

    let mut grouped = BTreeMap::<(String, LoadNode), BTreeMap<String, Vec<LoadTerm>>>::new();
    for quad in quads {
        grouped
            .entry((quad.graph.clone(), quad.subject.clone()))
            .or_default()
            .entry(quad.predicate.clone())
            .or_default()
            .push(quad.object.clone());
    }
    let mut nodes = Vec::with_capacity(grouped.len());
    for ((graph, subject), predicates) in grouped {
        let mut node = Map::new();
        node.insert(
            "@id".to_owned(),
            Value::String(node_id(&graph, &subject, &structural)?),
        );
        node.insert("@graph".to_owned(), Value::String(graph.clone()));
        for (predicate, mut objects) in predicates {
            objects.sort();
            objects.dedup();
            if predicate == RDF_TYPE {
                let encoded = objects
                    .iter()
                    .map(|term| match term {
                        LoadTerm::Iri(iri) => Ok(Value::String(iri.clone())),
                        _ => Err("rdf:type object must be an IRI".into()),
                    })
                    .collect::<LoadResult<Vec<_>>>()?;
                node.insert("@type".to_owned(), Value::Array(encoded));
            } else {
                let encoded = objects
                    .iter()
                    .map(|term| term_value(&graph, term, &structural))
                    .collect::<LoadResult<Vec<_>>>()?;
                node.insert(predicate, Value::Array(encoded));
            }
        }
        nodes.push(Value::Object(node));
    }
    let transaction = serde_json::json!({"@graph": nodes});
    let mut mapping_material = Vec::new();
    for ((graph, source), mapped) in &structural {
        mapping_material.extend_from_slice(graph.as_bytes());
        mapping_material.push(0);
        mapping_material.extend_from_slice(source.as_bytes());
        mapping_material.push(0);
        mapping_material.extend_from_slice(mapped.as_bytes());
        mapping_material.push(b'\n');
    }
    Ok((
        transaction,
        ContentHash::of_bytes(&mapping_material),
        structural.len(),
    ))
}

fn validate_blank(label: &str) -> LoadResult<()> {
    if !label.starts_with("_:") || label.len() <= 2 || label.as_bytes().contains(&0) {
        return Err("ontology profile blank node invalid".into());
    }
    Ok(())
}

fn node_id(
    graph: &str,
    node: &LoadNode,
    structural: &BTreeMap<(String, String), String>,
) -> LoadResult<String> {
    match node {
        LoadNode::Iri(iri) => Ok(iri.clone()),
        LoadNode::Blank(label) => structural
            .get(&(graph.to_owned(), label.clone()))
            .cloned()
            .ok_or_else(|| "ontology profile blank node mapping missing".into()),
    }
}

fn term_value(
    graph: &str,
    term: &LoadTerm,
    structural: &BTreeMap<(String, String), String>,
) -> LoadResult<Value> {
    match term {
        LoadTerm::Iri(iri) => Ok(serde_json::json!({"@id": iri})),
        LoadTerm::Blank(label) => Ok(serde_json::json!({
            "@id": structural
                .get(&(graph.to_owned(), label.clone()))
                .ok_or("ontology profile blank node mapping missing")?
        })),
        LoadTerm::Literal {
            lexical,
            datatype: _,
            language: Some(language),
        } => Ok(serde_json::json!({"@value": lexical, "@language": language})),
        LoadTerm::Literal {
            lexical,
            datatype,
            language: None,
        } => Ok(serde_json::json!({"@value": lexical, "@type": datatype})),
    }
}

fn validate_iri(value: &str) -> LoadResult<()> {
    if value.is_empty()
        || value.starts_with("_:")
        || value.as_bytes().contains(&0)
        || !value.contains(':')
    {
        return Err("ontology profile IRI invalid".into());
    }
    Ok(())
}
