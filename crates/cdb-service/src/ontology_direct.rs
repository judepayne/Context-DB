//! Read-only, snapshot-pinned ontology lookup against a raw FIBO bootstrap.
//!
//! This host deliberately does not build an in-memory ontology catalog. Every
//! lookup reopens Fluree with a read-only name service, verifies the pinned
//! head, and queries only the named graphs derived from the embedded source
//! inventory.

use cdb_backend_fluree::official_bootstrap::{verify_official_raw_bootstrap, FiboBootstrapReceipt};
use cdb_core::{id::ContentHash, CanonicalValue as V};
use cdb_provider_pi::ontology_bridge::{OntologyToolError, OntologyToolHost};
use fluree_db_api::{FlureeBuilder, NameServiceMode, TimeSpec};
use fluree_db_nameservice::file::FileNameService;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex, OnceLock,
};
use std::time::{Duration, Instant};

const AGREEMENTS_SCOPE: &str = "FND/Agreements/Agreements";
const COMMERCIAL_LOANS_SCOPE: &str = "LOAN/LoansSpecific/CommercialLoans";
const PARTY_BACKGROUND_SCOPE: &str = "party-background";
const AGREEMENTS_INVENTORY: &str =
    include_str!("../../../fixtures/conformance/p5_7/official-agreements-closure.json");
const COMMERCIAL_LOANS_INVENTORY: &str =
    include_str!("../../../fixtures/conformance/p6/official-commercial-loans-closure.json");
const PARTY_BACKGROUND_INVENTORY: &str =
    include_str!("../../../fixtures/conformance/party-background-closure.json");
const MAX_QUERY_ROWS: usize = 4096;
const MAX_QUERY_BYTES: usize = 512 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const QUERY_DEADLINE: Duration = Duration::from_secs(30);
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDFS_CLASS: &str = "http://www.w3.org/2000/01/rdf-schema#Class";
const RDF_PROPERTY: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#Property";
const RDFS_DATATYPE: &str = "http://www.w3.org/2000/01/rdf-schema#Datatype";
const OWL_CLASS: &str = "http://www.w3.org/2002/07/owl#Class";
const OWL_OBJECT_PROPERTY: &str = "http://www.w3.org/2002/07/owl#ObjectProperty";
const OWL_DATATYPE_PROPERTY: &str = "http://www.w3.org/2002/07/owl#DatatypeProperty";
const OWL_ANNOTATION_PROPERTY: &str = "http://www.w3.org/2002/07/owl#AnnotationProperty";
const OWL_NAMED_INDIVIDUAL: &str = "http://www.w3.org/2002/07/owl#NamedIndividual";
const OWL_ONTOLOGY: &str = "http://www.w3.org/2002/07/owl#Ontology";
const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
const RDF_LANG_STRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";
const MAX_AMBIGUITY_CANDIDATES: usize = 32;
const MAX_CACHED_RESPONSES: usize = 512;
const MAX_CACHED_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

const STANDARD_DATATYPES: &[&str] = &[
    "http://www.w3.org/2001/XMLSchema#boolean",
    "http://www.w3.org/2001/XMLSchema#date",
    "http://www.w3.org/2001/XMLSchema#dateTime",
    "http://www.w3.org/2001/XMLSchema#decimal",
    "http://www.w3.org/2001/XMLSchema#integer",
    "http://www.w3.org/2001/XMLSchema#string",
    RDF_LANG_STRING,
];

#[derive(Clone)]
pub(crate) struct DirectFlureeOntologyToolHost {
    path: PathBuf,
    ledger: String,
    t: i64,
    cid: String,
    inventory_root: String,
    source_quad_root: String,
    receipt: Arc<FiboBootstrapReceipt>,
    capture: String,
    graphs: Arc<[String]>,
    inventory_members: Arc<BTreeMap<String, InventoryMember>>,
    primary_graph: String,
    // This client and its cache are bound to the independently verified
    // `(t, CID)`. The current head is still checked before every response.
    reader: Arc<OnceLock<Arc<fluree_db_api::FlureeClient>>>,
    response_cache: Arc<Mutex<ResponseCache>>,
    busy: Arc<AtomicBool>,
}

#[derive(Default)]
struct ResponseCache {
    entries: BTreeMap<String, (Value, usize)>,
    insertion_order: std::collections::VecDeque<String>,
    bytes: usize,
}

impl ResponseCache {
    fn get(&self, key: &str) -> Option<Value> {
        self.entries.get(key).map(|(value, _)| value.clone())
    }

    fn insert(&mut self, key: String, value: Value, bytes: usize) {
        if bytes > MAX_CACHED_RESPONSE_BYTES || self.entries.contains_key(&key) {
            return;
        }
        while self.entries.len() >= MAX_CACHED_RESPONSES
            || self.bytes.saturating_add(bytes) > MAX_CACHED_RESPONSE_BYTES
        {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            if let Some((_, removed_bytes)) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(removed_bytes);
            }
        }
        self.bytes += bytes;
        self.insertion_order.push_back(key.clone());
        self.entries.insert(key, (value, bytes));
    }
}

#[derive(Deserialize)]
struct Inventory {
    file_count: usize,
    files: Vec<InventoryFile>,
    inventory_root: String,
}

#[derive(Deserialize)]
struct InventoryFile {
    path: String,
    #[serde(default = "official_source_kind")]
    source: String,
}

#[derive(Clone)]
struct InventoryMember {
    path: String,
    source: String,
}

fn official_source_kind() -> String {
    "official".into()
}

impl DirectFlureeOntologyToolHost {
    pub(crate) fn from_bootstrap(path: &Path) -> Result<Self, String> {
        Self::from_bootstrap_with_budget(
            path,
            Arc::new(AtomicBool::new(false)),
            Instant::now() + QUERY_DEADLINE,
        )
    }

    pub(crate) fn from_bootstrap_with_budget(
        path: &Path,
        cancellation: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<Self, String> {
        if cancellation.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err("ontology startup deadline exceeded".into());
        }
        let path = path
            .canonicalize()
            .map_err(|error| format!("ontology bootstrap path: {error}"))?;
        if !path.is_dir() {
            return Err("ontology bootstrap path is not a directory".into());
        }
        let bytes = std::fs::read(path.join("bootstrap.json"))
            .map_err(|error| format!("ontology bootstrap receipt: {error}"))?;
        if bytes.len() > 64 * 1024 {
            return Err("ontology bootstrap receipt exceeds limit".into());
        }
        let receipt: FiboBootstrapReceipt = serde_json::from_slice(&bytes)
            .map_err(|error| format!("ontology bootstrap receipt: {error}"))?;
        let inventory_text = match receipt.scope.as_str() {
            AGREEMENTS_SCOPE => AGREEMENTS_INVENTORY,
            COMMERCIAL_LOANS_SCOPE => COMMERCIAL_LOANS_INVENTORY,
            PARTY_BACKGROUND_SCOPE => PARTY_BACKGROUND_INVENTORY,
            _ => return Err("ontology bootstrap scope is not allowed".into()),
        };
        let inventory: Inventory = serde_json::from_str(inventory_text)
            .map_err(|error| format!("embedded ontology inventory: {error}"))?;
        if inventory.file_count != inventory.files.len()
            || inventory.inventory_root != receipt.source_inventory_root
        {
            return Err("embedded ontology inventory differs".into());
        }
        let inventory_members = inventory
            .files
            .iter()
            .map(|file| {
                if !matches!(file.source.as_str(), "official" | "local_extension") {
                    return Err("embedded ontology inventory source kind invalid".into());
                }
                Ok((
                    graph_for_inventory_path(&file.path)?,
                    InventoryMember {
                        path: file.path.clone(),
                        source: file.source.clone(),
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let graphs = inventory_members.keys().cloned().collect::<BTreeSet<_>>();
        if graphs.is_empty() || graphs.iter().cloned().collect::<Vec<_>>() != receipt.graph_set {
            return Err("ontology bootstrap graph allowlist is empty".into());
        }
        let capture = ContentHash::of_bytes(
            format!(
                "ctxql-ontology-direct-capture/v2\0{}\0{}",
                receipt.exact_capture, receipt.loaded_quad_root
            )
            .as_bytes(),
        )
        .as_str()
        .to_owned();
        let primary_graph = if receipt.scope == PARTY_BACKGROUND_SCOPE {
            graph_for_inventory_path("assets/party-background/party-background.rdf")?
        } else {
            graph_for_inventory_path(&format!("fibo/{}.rdf", receipt.scope))?
        };
        let receipt = Arc::new(receipt);
        let host = Self {
            path,
            ledger: receipt.ledger.clone(),
            t: receipt.t,
            cid: receipt.cid.clone(),
            inventory_root: receipt.source_inventory_root.clone(),
            source_quad_root: receipt.source_quad_root.clone(),
            receipt,
            capture,
            graphs: graphs.into_iter().collect::<Vec<_>>().into(),
            inventory_members: Arc::new(inventory_members),
            primary_graph,
            reader: Arc::new(OnceLock::new()),
            response_cache: Arc::new(Mutex::new(ResponseCache::default())),
            busy: Arc::new(AtomicBool::new(false)),
        };
        run_with_budget(host.clone(), cancellation, deadline, |probe| async move {
            verify_official_raw_bootstrap(&probe.path, &probe.receipt)
                .await
                .map(|_| ())
                .map_err(|error| format!("ontology content verification: {error}"))
        })?;
        Ok(host)
    }

    pub(crate) fn provenance(&self) -> Result<V, String> {
        V::object([
            ("mode".into(), V::string("fluree-direct/v1")),
            ("capture".into(), V::string(&self.capture)),
            ("inventory_root".into(), V::string(&self.inventory_root)),
            ("source_quad_root".into(), V::string(&self.source_quad_root)),
            ("t".into(), V::string(self.t.to_string())),
            ("cid".into(), V::string(&self.cid)),
        ])
        .map_err(|_| "ontology lookup provenance invalid".into())
    }

    async fn reader(&self) -> Result<Arc<fluree_db_api::FlureeClient>, String> {
        if let Some(reader) = self.reader.get() {
            return Ok(reader.clone());
        }
        let nameservice =
            NameServiceMode::ReadOnly(Arc::new(FileNameService::new(self.path.as_path())));
        let reader = Arc::new(
            FlureeBuilder::file(self.path.to_string_lossy().into_owned())
                .without_indexing()
                .build_client_with_nameservice(nameservice)
                .await
                .map_err(|error| format!("ontology read-only open: {error}"))?,
        );
        // `busy` serializes normal initialization. Keep the first client if a
        // future caller races this path rather than changing the pinned view.
        let _ = self.reader.set(reader.clone());
        Ok(self.reader.get().cloned().unwrap_or(reader))
    }

    async fn lookup_async(
        &self,
        operation: &str,
        query: &str,
        limit: usize,
        requested_kind: Option<&str>,
    ) -> Result<Value, String> {
        let reader = self.reader().await?;
        let head = reader
            .ledger(&self.ledger)
            .await
            .map_err(|error| format!("ontology ledger open: {error}"))?;
        if head.t() != self.t
            || head
                .head_commit_id
                .as_ref()
                .map(ToString::to_string)
                .as_deref()
                != Some(self.cid.as_str())
        {
            return Err("ontology ledger head drifted from bootstrap capture".into());
        }
        let normalized_query = if operation == "resolve_exact" {
            expand_compact_identifier(query).unwrap_or_else(|| query.to_owned())
        } else {
            query.to_owned()
        };
        let identifier_resolution = operation == "resolve_exact"
            && valid_sparql_iri(&normalized_query)
            && (normalized_query != query || query.contains(':'));
        let cache_key = serde_json::to_string(&(operation, query, limit, requested_kind))
            .map_err(|error| format!("ontology cache key: {error}"))?;
        if let Some(response) = self
            .response_cache
            .lock()
            .map_err(|_| "ontology response cache poisoned".to_owned())?
            .get(&cache_key)
        {
            return Ok(response);
        }
        let mut search_truncated = false;
        let mut resolution_truncated = false;
        let mut terms = if operation == "resolve_exact"
            && STANDARD_DATATYPES.contains(&normalized_query.as_str())
        {
            vec![standard_datatype_term(&normalized_query)]
        } else {
            let query_limit = if operation == "resolve_exact" {
                if identifier_resolution {
                    1
                } else {
                    MAX_AMBIGUITY_CANDIDATES + 1
                }
            } else {
                limit.saturating_add(1)
            };
            let select = self.select_query(
                operation,
                &normalized_query,
                query_limit,
                identifier_resolution,
                requested_kind,
            )?;
            let selected = execute_query(&reader, &self.ledger, self.t, &select).await?;
            let mut iris = selected_iris(&selected, query_limit)?;
            if operation == "resolve_exact" && !identifier_resolution && iris.len() == query_limit {
                resolution_truncated = true;
            }
            if operation != "resolve_exact" && iris.len() > limit {
                search_truncated = true;
                iris.truncate(limit);
            }
            if iris.is_empty() {
                Vec::new()
            } else {
                let details = self.detail_query(&iris);
                let value = execute_query(&reader, &self.ledger, self.t, &details).await?;
                project_terms(&value, &iris, &self.inventory_members, &self.primary_graph)?
            }
        };
        if operation == "search" && requested_kind.is_none_or(|kind| kind == "datatype") {
            let needle = query.to_lowercase();
            for datatype in STANDARD_DATATYPES {
                if local_name(datatype).is_some_and(|name| name.to_lowercase().contains(&needle))
                    && !terms.iter().any(|term| term["iri"] == *datatype)
                {
                    terms.push(standard_datatype_term(datatype));
                }
            }
            terms.sort_by(|left, right| left["iri"].as_str().cmp(&right["iri"].as_str()));
            if terms.len() > limit {
                search_truncated = true;
                terms.truncate(limit);
            }
        }
        if let Some(kind) = requested_kind {
            terms.retain(|term| response_kind_matches(term["kind"].as_str(), kind));
        }
        let resolution = if operation == "resolve_exact" {
            Some(resolution_projection(
                &terms,
                identifier_resolution,
                resolution_truncated,
            ))
        } else {
            None
        };
        if terms.len() > MAX_AMBIGUITY_CANDIDATES && operation == "resolve_exact" {
            terms.truncate(MAX_AMBIGUITY_CANDIDATES);
        }
        let response = json!({
            "schema": "ctxql-extraction-vocabulary-response/v2",
            "capture": self.capture,
            "inventory_root": self.inventory_root,
            "source_quad_root": self.source_quad_root,
            "t": self.t,
            "cid": self.cid,
            "operation": operation,
            "query": query,
            "normalized_query": normalized_query,
            "requested_kind": requested_kind,
            "namespace_mappings": namespace_mappings(),
            "page": { "limit": limit, "truncated": search_truncated, "cursor": Value::Null },
            "resolution": resolution,
            "terms": terms,
        });
        let response_bytes = serde_json::to_vec(&response)
            .map_err(|error| format!("ontology response encoding: {error}"))?;
        if response_bytes.len() > MAX_RESPONSE_BYTES {
            return Err("ontology response exceeds limit".into());
        }
        self.response_cache
            .lock()
            .map_err(|_| "ontology response cache poisoned".to_owned())?
            .insert(cache_key, response.clone(), response_bytes.len());
        Ok(response)
    }

    fn graph_values(&self) -> String {
        self.graphs
            .iter()
            .map(|graph| format!("<{graph}>"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn select_query(
        &self,
        operation: &str,
        query: &str,
        limit: usize,
        identifier_resolution: bool,
        requested_kind: Option<&str>,
    ) -> Result<String, String> {
        let graphs = self.graph_values();
        let declarations = declaration_values_for(requested_kind);
        if operation == "resolve_exact" && identifier_resolution {
            if !valid_sparql_iri(query) {
                return Err("ontology term IRI is invalid".into());
            }
            Ok(format!(
                "SELECT DISTINCT ?term WHERE {{ VALUES ?g {{ {graphs} }} GRAPH ?g {{ VALUES ?term {{ <{query}> }} ?term <{RDF_TYPE}> ?decl . VALUES ?decl {{ {declarations} }} }} }} ORDER BY ?term LIMIT 1"
            ))
        } else if operation == "resolve_exact" {
            // Fetch the complete bounded exact candidate set before deciding
            // uniqueness. The requested response page is never evidence that
            // another exact homonym does not exist.
            let needle = sparql_string(&query.to_lowercase());
            Ok(format!(
                "SELECT DISTINCT ?term WHERE {{ VALUES ?g {{ {graphs} }} GRAPH ?g {{ ?term <{RDF_TYPE}> ?decl . VALUES ?decl {{ {declarations} }} {{ FILTER(STRENDS(LCASE(STR(?term)), CONCAT(\"#\", {needle})) || STRENDS(LCASE(STR(?term)), CONCAT(\"/\", {needle}))) }} UNION {{ ?term ?text_pred ?text . VALUES ?text_pred {{ <http://www.w3.org/2000/01/rdf-schema#label> <http://www.w3.org/2004/02/skos/core#prefLabel> <http://www.w3.org/2004/02/skos/core#altLabel> <http://www.w3.org/2004/02/skos/core#hiddenLabel> }} FILTER(ISLITERAL(?text) && LCASE(STR(?text)) = {needle}) }} }} }} ORDER BY ?term LIMIT {limit}"
            ))
        } else if operation == "search" {
            let needle = sparql_string(&query.to_lowercase());
            Ok(format!(
                "SELECT DISTINCT ?term WHERE {{ VALUES ?g {{ {graphs} }} GRAPH ?g {{ ?term <{RDF_TYPE}> ?decl . VALUES ?decl {{ {declarations} }} {{ FILTER(CONTAINS(LCASE(STR(?term)), {needle})) }} UNION {{ ?term ?text_pred ?text . VALUES ?text_pred {{ <http://www.w3.org/2000/01/rdf-schema#label> <http://www.w3.org/2004/02/skos/core#prefLabel> <http://www.w3.org/2004/02/skos/core#altLabel> <http://www.w3.org/2004/02/skos/core#hiddenLabel> <http://www.w3.org/2000/01/rdf-schema#comment> <http://www.w3.org/2004/02/skos/core#definition> }} FILTER(ISLITERAL(?text) && CONTAINS(LCASE(STR(?text)), {needle})) }} }} }} ORDER BY ?term LIMIT {limit}"
            ))
        } else {
            if !valid_sparql_iri(query) {
                return Err("ontology term IRI is invalid".into());
            }
            Ok(format!(
                "SELECT DISTINCT ?term WHERE {{ VALUES ?g {{ {graphs} }} GRAPH ?g {{ VALUES ?term {{ <{query}> }} ?term <{RDF_TYPE}> ?decl . VALUES ?decl {{ {declarations} }} }} }} LIMIT 1"
            ))
        }
    }

    fn detail_query(&self, iris: &[String]) -> String {
        let graphs = self.graph_values();
        let terms = iris
            .iter()
            .map(|iri| format!("<{iri}>"))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "SELECT ?term ?source_graph ?type ?super ?domain ?range ?label ?definition ?synonym ?deprecated WHERE {{ VALUES ?source_graph {{ {graphs} }} VALUES ?term {{ {terms} }} GRAPH ?source_graph {{ {{ ?term <{RDF_TYPE}> ?type }} UNION {{ ?term <http://www.w3.org/2000/01/rdf-schema#subClassOf> ?super }} UNION {{ ?term <http://www.w3.org/2000/01/rdf-schema#subPropertyOf> ?super }} UNION {{ ?term <http://www.w3.org/2000/01/rdf-schema#domain> ?domain }} UNION {{ ?term <http://www.w3.org/2000/01/rdf-schema#range> ?range }} UNION {{ ?term ?label_pred ?label . VALUES ?label_pred {{ <http://www.w3.org/2000/01/rdf-schema#label> <http://www.w3.org/2004/02/skos/core#prefLabel> }} FILTER(ISLITERAL(?label)) }} UNION {{ ?term ?definition_pred ?definition . VALUES ?definition_pred {{ <http://www.w3.org/2000/01/rdf-schema#comment> <http://www.w3.org/2004/02/skos/core#definition> }} FILTER(ISLITERAL(?definition)) }} UNION {{ ?term ?synonym_pred ?synonym . VALUES ?synonym_pred {{ <http://www.w3.org/2004/02/skos/core#altLabel> <http://www.w3.org/2004/02/skos/core#hiddenLabel> }} FILTER(ISLITERAL(?synonym)) }} UNION {{ ?term <http://www.w3.org/2002/07/owl#deprecated> ?deprecated }} }} }} ORDER BY ?term ?source_graph LIMIT {}",
            MAX_QUERY_ROWS + 1
        )
    }
}

impl OntologyToolHost for DirectFlureeOntologyToolHost {
    fn lookup(&self, request: &Value) -> Result<Value, OntologyToolError> {
        self.lookup_with_budget(
            request,
            Arc::new(AtomicBool::new(false)),
            Instant::now() + QUERY_DEADLINE,
        )
    }
}

impl DirectFlureeOntologyToolHost {
    pub(crate) fn lookup_with_budget(
        &self,
        request: &Value,
        cancellation: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<Value, OntologyToolError> {
        let object = request.as_object().ok_or(OntologyToolError::Denied)?;
        if object.len() < 2
            || object.len() > 4
            || object
                .keys()
                .any(|key| !matches!(key.as_str(), "operation" | "query" | "limit" | "kind"))
        {
            return Err(OntologyToolError::Denied);
        }
        let operation = object
            .get("operation")
            .and_then(Value::as_str)
            .filter(|value| {
                matches!(
                    *value,
                    "search" | "resolve_exact" | "describe" | "hierarchy" | "vocabulary_status"
                )
            })
            .ok_or(OntologyToolError::Denied)?;
        let query = object
            .get("query")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or(OntologyToolError::Denied)?;
        let limit = match object.get("limit") {
            Some(value) => value.as_u64().ok_or(OntologyToolError::Denied)?,
            None => 10,
        };
        let requested_kind = match object.get("kind") {
            Some(value) => {
                let value = value.as_str().ok_or(OntologyToolError::Denied)?;
                if !matches!(
                    value,
                    "class"
                        | "property"
                        | "object_property"
                        | "datatype_property"
                        | "annotation_property"
                        | "generic_property"
                        | "conflicting_property"
                        | "datatype"
                ) {
                    return Err(OntologyToolError::Denied);
                }
                Some(value)
            }
            None => None,
        };
        if !(1..=20).contains(&limit)
            || (!matches!(operation, "search" | "resolve_exact") && !valid_sparql_iri(query))
        {
            return Err(OntologyToolError::Denied);
        }
        let operation = operation.to_owned();
        let query = query.to_owned();
        let requested_kind = requested_kind.map(str::to_owned);
        run_with_budget(
            self.clone(),
            cancellation,
            deadline,
            move |host| async move {
                host.lookup_async(
                    &operation,
                    &query,
                    limit as usize,
                    requested_kind.as_deref(),
                )
                .await
            },
        )
        .map_err(|_| OntologyToolError::Denied)
    }
}

async fn execute_query(
    reader: &fluree_db_api::FlureeClient,
    ledger: &str,
    t: i64,
    query: &str,
) -> Result<Value, String> {
    let result = reader
        .graph_at(ledger, TimeSpec::AtT(t))
        .query()
        .sparql(query)
        .execute_formatted()
        .await
        .map_err(|error| format!("ontology query: {error}"))?;
    if serde_json::to_vec(&result)
        .map_err(|error| format!("ontology query encoding: {error}"))?
        .len()
        > MAX_QUERY_BYTES
    {
        return Err("ontology query result exceeds limit".into());
    }
    let rows = bindings(&result)?;
    if rows.len() > MAX_QUERY_ROWS {
        return Err("ontology query row limit exceeded".into());
    }
    Ok(result)
}

fn selected_iris(value: &Value, limit: usize) -> Result<Vec<String>, String> {
    let mut iris = Vec::new();
    for row in bindings(value)? {
        let iri = iri_cell(row, "term").ok_or("ontology query returned a non-IRI term")?;
        if !valid_sparql_iri(iri) {
            return Err("ontology query returned an invalid term IRI".into());
        }
        if !iris.iter().any(|candidate| candidate == iri) {
            iris.push(iri.to_owned());
        }
        if iris.len() == limit {
            break;
        }
    }
    Ok(iris)
}

#[derive(Default)]
struct TermProjection {
    types: BTreeSet<String>,
    super_terms: BTreeSet<String>,
    domains: BTreeMap<String, BTreeSet<String>>,
    ranges: BTreeMap<String, BTreeSet<String>>,
    labels: BTreeSet<String>,
    definitions: BTreeSet<String>,
    aliases: BTreeSet<String>,
    source_graphs: BTreeSet<String>,
    anonymous_super: bool,
    anonymous_domain: bool,
    anonymous_range: bool,
    unsupported_expression: bool,
    deprecated: bool,
}

fn project_terms(
    value: &Value,
    selected: &[String],
    inventory: &BTreeMap<String, InventoryMember>,
    primary_graph: &str,
) -> Result<Vec<Value>, String> {
    let mut terms = selected
        .iter()
        .map(|iri| (iri.clone(), TermProjection::default()))
        .collect::<BTreeMap<_, _>>();
    for row in bindings(value)? {
        let iri = iri_cell(row, "term").ok_or("ontology detail returned a non-IRI term")?;
        let term = terms
            .get_mut(iri)
            .ok_or("ontology detail returned an unselected term")?;
        let graph = iri_cell(row, "source_graph").ok_or("ontology detail omitted source graph")?;
        if !inventory.contains_key(graph) {
            return Err("ontology detail returned a graph outside approved inventory".into());
        }
        term.source_graphs.insert(graph.to_owned());
        insert_iri(row, "type", &mut term.types)?;
        insert_named_or_anonymous(
            row,
            "super",
            graph,
            None,
            &mut term.anonymous_super,
            &mut term.unsupported_expression,
            Some(&mut term.super_terms),
        )?;
        insert_named_or_anonymous(
            row,
            "domain",
            graph,
            Some(&mut term.domains),
            &mut term.anonymous_domain,
            &mut term.unsupported_expression,
            None,
        )?;
        insert_named_or_anonymous(
            row,
            "range",
            graph,
            Some(&mut term.ranges),
            &mut term.anonymous_range,
            &mut term.unsupported_expression,
            None,
        )?;
        insert_literal(row, "label", &mut term.labels)?;
        insert_literal(row, "definition", &mut term.definitions)?;
        insert_literal(row, "synonym", &mut term.aliases)?;
        if literal_cell(row, "deprecated").is_some_and(|value| value.eq_ignore_ascii_case("true")) {
            term.deprecated = true;
        }
    }
    selected
        .iter()
        .map(|iri| {
            let term = terms.remove(iri).ok_or("selected ontology term missing")?;
            let kind = term_kind(&term.types).ok_or("ontology term has no supported kind")?;
            let inventory_members = term
                .source_graphs
                .iter()
                .map(|graph| &inventory.get(graph).expect("validated graph").path)
                .collect::<Vec<_>>();
            let source_kinds = term
                .source_graphs
                .iter()
                .map(|graph| &inventory.get(graph).expect("validated graph").source)
                .collect::<BTreeSet<_>>();
            let official_source = source_kinds.iter().all(|kind| kind.as_str() == "official");
            let imported = term
                .source_graphs
                .iter()
                .any(|graph| graph != primary_graph);
            let domain_constraints = named_constraints(&term.domains);
            let range_constraints = named_constraints(&term.ranges);
            let constraints_complete = !term.anonymous_domain
                && !term.anonymous_range
                && !term.anonymous_super
                && !term.unsupported_expression;
            Ok(json!({
                "iri": iri,
                "kind": kind,
                "declarations": term.types,
                "status": if term.deprecated { "deprecated" } else { "loaded_uncertified" },
                "deprecated": term.deprecated,
                "extraction_eligible": !term.deprecated,
                "approved_inventory_member": true,
                "official_source": official_source,
                "source_kinds": source_kinds,
                "imported": imported,
                "inventory_members": inventory_members,
                "source_graphs": term.source_graphs,
                "super_terms": term.super_terms,
                "labels": term.labels,
                "definitions": term.definitions,
                "aliases": term.aliases,
                "constraints": {
                    "domains": domain_constraints,
                    "ranges": range_constraints,
                    "anonymous_domain_present": term.anonymous_domain,
                    "anonymous_range_present": term.anonymous_range,
                    "anonymous_super_present": term.anonymous_super,
                    "unsupported_expression_present": term.unsupported_expression,
                    "complete": constraints_complete,
                },
            }))
        })
        .collect()
}

fn bindings(value: &Value) -> Result<&Vec<Value>, String> {
    value
        .get("results")
        .and_then(|results| results.get("bindings"))
        .and_then(Value::as_array)
        .ok_or_else(|| "malformed ontology query result".into())
}

fn cell<'a>(row: &'a Value, key: &str, expected: &[&str]) -> Option<&'a str> {
    let value = row.get(key)?.as_object()?;
    expected
        .contains(&value.get("type")?.as_str()?)
        .then(|| value.get("value")?.as_str())?
}

fn iri_cell<'a>(row: &'a Value, key: &str) -> Option<&'a str> {
    cell(row, key, &["uri", "iri"])
}

fn literal_cell<'a>(row: &'a Value, key: &str) -> Option<&'a str> {
    cell(row, key, &["literal", "typed-literal"])
}

fn insert_iri(row: &Value, key: &str, values: &mut BTreeSet<String>) -> Result<(), String> {
    if row.get(key).is_some() {
        let value = iri_cell(row, key).ok_or("ontology detail IRI has invalid shape")?;
        if !valid_sparql_iri(value) {
            return Err("ontology detail contains an invalid IRI".into());
        }
        values.insert(value.to_owned());
    }
    Ok(())
}

fn insert_literal(row: &Value, key: &str, values: &mut BTreeSet<String>) -> Result<(), String> {
    if row.get(key).is_some() {
        let value = literal_cell(row, key).ok_or("ontology detail literal has invalid shape")?;
        if value.len() > 8192 {
            return Err("ontology detail literal exceeds limit".into());
        }
        values.insert(value.to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_named_or_anonymous(
    row: &Value,
    key: &str,
    graph: &str,
    constraints: Option<&mut BTreeMap<String, BTreeSet<String>>>,
    anonymous: &mut bool,
    unsupported: &mut bool,
    supers: Option<&mut BTreeSet<String>>,
) -> Result<(), String> {
    let Some(value) = row.get(key) else {
        return Ok(());
    };
    if let Some(iri) = iri_cell(row, key) {
        if !valid_sparql_iri(iri) {
            return Err("ontology constraint contains an invalid IRI".into());
        }
        if let Some(values) = constraints {
            values
                .entry(iri.to_owned())
                .or_default()
                .insert(graph.to_owned());
        }
        if let Some(values) = supers {
            values.insert(iri.to_owned());
        }
    } else if value.get("type").and_then(Value::as_str) == Some("bnode") {
        *anonymous = true;
    } else {
        *unsupported = true;
    }
    Ok(())
}

fn named_constraints(values: &BTreeMap<String, BTreeSet<String>>) -> Vec<Value> {
    values
        .iter()
        .map(|(iri, graphs)| {
            json!({
                "iri": iri,
                "provenance": "direct",
                "source_graphs": graphs,
            })
        })
        .collect()
}

fn term_kind(types: &BTreeSet<String>) -> Option<&'static str> {
    if types.contains(OWL_CLASS) || types.contains(RDFS_CLASS) {
        Some("class")
    } else if types.contains(RDFS_DATATYPE) {
        Some("datatype")
    } else {
        let object = types.contains(OWL_OBJECT_PROPERTY);
        let datatype = types.contains(OWL_DATATYPE_PROPERTY);
        let annotation = types.contains(OWL_ANNOTATION_PROPERTY);
        let specific_count = usize::from(object) + usize::from(datatype) + usize::from(annotation);
        if specific_count > 1 {
            return Some("conflicting_property");
        }
        if object {
            return Some("object_property");
        }
        if datatype {
            return Some("datatype_property");
        }
        if annotation {
            return Some("annotation_property");
        }
        if types.contains(RDF_PROPERTY) {
            return Some("generic_property");
        }
        if types.contains(OWL_ONTOLOGY) {
            Some("vocabulary")
        } else if types.contains(OWL_NAMED_INDIVIDUAL) {
            Some("individual")
        } else {
            None
        }
    }
}

fn resolution_projection(terms: &[Value], identifier_resolution: bool, truncated: bool) -> Value {
    let complete = !truncated;
    let status = if terms.is_empty() {
        "not_found"
    } else if terms.len() == 1 && complete {
        "unique"
    } else {
        "ambiguous"
    };
    let candidates = terms
        .iter()
        .take(MAX_AMBIGUITY_CANDIDATES)
        .filter_map(|term| term["iri"].as_str())
        .collect::<Vec<_>>();
    json!({
        "status": status,
        "match": if status == "unique" { candidates.first().copied() } else { None },
        "candidates": candidates,
        "candidates_truncated": terms.len() > MAX_AMBIGUITY_CANDIDATES || !complete,
        "complete": complete,
        "rule": if identifier_resolution { "exact_identifier" } else { "unique_exact_lexical" },
    })
}

fn response_kind_matches(actual: Option<&str>, requested: &str) -> bool {
    actual == Some(requested)
        || (requested == "property"
            && matches!(
                actual,
                Some(
                    "object_property"
                        | "datatype_property"
                        | "annotation_property"
                        | "generic_property"
                        | "conflicting_property"
                )
            ))
}

fn namespace_mappings() -> Value {
    json!({
        "commons": "https://www.omg.org/spec/Commons/",
        "ctxql-party-background": "https://ctxql.org/ontology/party-background/",
        "fibo": "https://spec.edmcouncil.org/fibo/ontology/",
        "lcc": "https://www.omg.org/spec/LCC/",
        "owl": "http://www.w3.org/2002/07/owl#",
        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
        "skos": "http://www.w3.org/2004/02/skos/core#",
        "xsd": XSD,
    })
}

fn expand_compact_identifier(value: &str) -> Option<String> {
    let (prefix, local) = value.split_once(':')?;
    if local.is_empty() || local.chars().any(char::is_control) {
        return None;
    }
    let namespace = match prefix {
        "commons" => "https://www.omg.org/spec/Commons/",
        "ctxql-party-background" => "https://ctxql.org/ontology/party-background/",
        "fibo" => "https://spec.edmcouncil.org/fibo/ontology/",
        "lcc" => "https://www.omg.org/spec/LCC/",
        "owl" => "http://www.w3.org/2002/07/owl#",
        "rdf" => "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "rdfs" => "http://www.w3.org/2000/01/rdf-schema#",
        "skos" => "http://www.w3.org/2004/02/skos/core#",
        "xsd" => XSD,
        _ => return None,
    };
    Some(format!("{namespace}{local}"))
}

fn standard_datatype_term(iri: &str) -> Value {
    json!({
        "iri": iri,
        "kind": "datatype",
        "declarations": [RDFS_DATATYPE],
        "status": "standard",
        "deprecated": false,
        "extraction_eligible": true,
        "approved_inventory_member": false,
        "official_source": false,
        "source_kinds": [],
        "imported": false,
        "inventory_members": [],
        "source_graphs": [],
        "super_terms": [],
        "labels": [local_name(iri).unwrap_or(iri)],
        "definitions": [],
        "aliases": [],
        "constraints": {
            "domains": [], "ranges": [],
            "anonymous_domain_present": false,
            "anonymous_range_present": false,
            "anonymous_super_present": false,
            "unsupported_expression_present": false,
            "complete": true,
        },
    })
}

fn local_name(iri: &str) -> Option<&str> {
    iri.rsplit(['#', '/'])
        .next()
        .filter(|value| !value.is_empty())
}

fn declaration_values_for(kind: Option<&str>) -> String {
    let declarations: &[&str] = match kind {
        Some("class") => &[OWL_CLASS, RDFS_CLASS],
        Some("property") => &[
            RDF_PROPERTY,
            OWL_OBJECT_PROPERTY,
            OWL_DATATYPE_PROPERTY,
            OWL_ANNOTATION_PROPERTY,
        ],
        Some("object_property") => &[OWL_OBJECT_PROPERTY],
        Some("datatype_property") => &[OWL_DATATYPE_PROPERTY],
        Some("annotation_property") => &[OWL_ANNOTATION_PROPERTY],
        Some("generic_property") => &[RDF_PROPERTY],
        Some("conflicting_property") => &[
            OWL_OBJECT_PROPERTY,
            OWL_DATATYPE_PROPERTY,
            OWL_ANNOTATION_PROPERTY,
        ],
        Some("datatype") => &[RDFS_DATATYPE],
        _ => &[
            OWL_CLASS,
            RDFS_CLASS,
            RDF_PROPERTY,
            OWL_OBJECT_PROPERTY,
            OWL_DATATYPE_PROPERTY,
            OWL_ANNOTATION_PROPERTY,
            RDFS_DATATYPE,
            OWL_NAMED_INDIVIDUAL,
            OWL_ONTOLOGY,
        ],
    };
    declarations
        .iter()
        .map(|iri| format!("<{iri}>"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn graph_for_inventory_path(path: &str) -> Result<String, String> {
    let without_suffix = path
        .strip_suffix(".rdf")
        .ok_or_else(|| "embedded ontology inventory path has invalid suffix".to_owned())?;
    if let Some(name) = without_suffix.strip_prefix("commons/") {
        valid_inventory_component(name)?;
        Ok(format!("https://www.omg.org/spec/Commons/{name}/"))
    } else if let Some(name) = without_suffix.strip_prefix("lcc/") {
        valid_inventory_component(name)?;
        Ok(format!("https://www.omg.org/spec/LCC/{name}/"))
    } else if let Some(name) = without_suffix.strip_prefix("fibo/") {
        valid_inventory_component(name)?;
        Ok(format!("https://spec.edmcouncil.org/fibo/ontology/{name}/"))
    } else if without_suffix == "assets/party-background/party-background" {
        Ok("https://ctxql.org/ontology/party-background/".into())
    } else {
        Err("embedded ontology inventory path has invalid prefix".into())
    }
}

fn valid_inventory_component(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        Err("embedded ontology inventory path is unsafe".into())
    } else {
        Ok(())
    }
}

fn valid_sparql_iri(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.contains(':')
        && !value
            .chars()
            .any(|character| character <= '\u{20}' || "<>\"{}|^`\\".contains(character))
}

fn sparql_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            value if value.is_control() => {
                use std::fmt::Write;
                let _ = write!(escaped, "\\u{:04X}", value as u32);
            }
            value => escaped.push(value),
        }
    }
    escaped.push('"');
    escaped
}

#[cfg(test)]
fn run_with_deadline<T, F, Fut>(host: DirectFlureeOntologyToolHost, task: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(DirectFlureeOntologyToolHost) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, String>> + 'static,
{
    run_with_budget(
        host,
        Arc::new(AtomicBool::new(false)),
        Instant::now() + QUERY_DEADLINE,
        task,
    )
}

fn run_with_budget<T, F, Fut>(
    host: DirectFlureeOntologyToolHost,
    cancellation: Arc<AtomicBool>,
    deadline: Instant,
    task: F,
) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(DirectFlureeOntologyToolHost) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, String>> + 'static,
{
    let deadline = deadline.min(Instant::now() + QUERY_DEADLINE);
    if cancellation.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err("ontology query cancelled or deadline exceeded".into());
    }
    if host.busy.swap(true, Ordering::AcqRel) {
        return Err("ontology lookup already running".into());
    }
    let busy = host.busy.clone();
    let busy_for_thread = busy.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name("ctxql-ontology-readonly".into())
        .spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("ontology runtime: {error}"))
                .and_then(|runtime| {
                    runtime.block_on(async {
                        tokio::select! {
                            result = task(host) => result,
                            _ = async {
                                while !cancellation.load(Ordering::Acquire) && Instant::now() < deadline {
                                    tokio::time::sleep(Duration::from_millis(5)).await;
                                }
                            } => Err(if cancellation.load(Ordering::Acquire) {
                                "ontology query cancelled"
                            } else {
                                "ontology query deadline exceeded"
                            }.to_owned()),
                        }
                    })
                });
            busy_for_thread.store(false, Ordering::Release);
            let _ = sender.send(result);
        });
    if let Err(error) = thread {
        busy.store(false, Ordering::Release);
        return Err(format!("ontology lookup thread: {error}"));
    }
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()) + Duration::from_secs(2))
        .map_err(|_| "ontology query deadline exceeded".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_receipt() -> FiboBootstrapReceipt {
        FiboBootstrapReceipt {
            schema: "ctxql-fibo-bootstrap/v3".into(),
            status: "loaded_uncertified".into(),
            certified: false,
            scope: AGREEMENTS_SCOPE.into(),
            storage_path: "/does/not/exist".into(),
            source_cache_path: "/does/not/exist".into(),
            ledger: "ctxql/poc:main".into(),
            t: 1,
            cid: "wrong".into(),
            source_file_count: 0,
            source_inventory_root: "sha256:wrong".into(),
            source_quad_count: 0,
            source_quad_root: "sha256:wrong".into(),
            submitted_quad_count: 0,
            omitted_quad_count: 0,
            omitted_quads: vec![],
            omitted_quad_root: "sha256:wrong".into(),
            loaded_quad_root: "sha256:wrong".into(),
            graph_set: vec![],
            graph_set_root: "sha256:wrong".into(),
            structural_algorithm: "test".into(),
            normalization_identity: "test".into(),
            structural_mapping_root: "sha256:wrong".into(),
            loader_identity: "test".into(),
            backend_identity: "test".into(),
            exact_capture: "sha256:wrong".into(),
            transaction_quad_count: 0,
            transaction_bytes: 1,
        }
    }

    #[test]
    fn historical_v2_receipt_cannot_construct_current_host() {
        let temp = tempfile::tempdir().unwrap();
        let mut historical = serde_json::to_value(test_receipt()).unwrap();
        historical["schema"] = json!("ctxql-fibo-bootstrap/v2");
        historical
            .as_object_mut()
            .unwrap()
            .remove("normalization_identity");
        std::fs::write(
            temp.path().join("bootstrap.json"),
            serde_json::to_vec(&historical).unwrap(),
        )
        .unwrap();
        assert!(DirectFlureeOntologyToolHost::from_bootstrap(temp.path()).is_err());
    }

    #[test]
    fn sparql_inputs_cannot_break_fixed_templates() {
        let attack = "x\") } UNION { ?s ?p ?o } #\n";
        let escaped = sparql_string(attack);
        assert!(escaped.starts_with('"') && escaped.ends_with('"'));
        assert!(escaped.contains("\\\"") && escaped.contains("\\n"));
        assert!(!valid_sparql_iri(
            "https://example.test/x> } UNION { ?s ?p ?o"
        ));
    }

    #[test]
    fn embedded_inventory_paths_produce_only_fixed_graph_iris() {
        assert_eq!(
            graph_for_inventory_path("fibo/FND/Agreements/Agreements.rdf").unwrap(),
            "https://spec.edmcouncil.org/fibo/ontology/FND/Agreements/Agreements/"
        );
        assert!(graph_for_inventory_path("fibo/../foreign.rdf").is_err());
        assert!(graph_for_inventory_path("https://foreign.test/g.rdf").is_err());
    }

    #[test]
    fn v2_projection_preserves_property_kinds_imports_text_and_incompleteness() {
        let graph = "https://www.omg.org/spec/Commons/Test/";
        let term = "https://www.omg.org/spec/Commons/Test/hasValue";
        let uri = |value: &str| json!({"type":"uri","value":value});
        let literal = |value: &str| json!({"type":"literal","value":value});
        let rows = json!({"results":{"bindings":[
            {"term":uri(term),"source_graph":uri(graph),"type":uri(RDF_PROPERTY)},
            {"term":uri(term),"source_graph":uri(graph),"type":uri(OWL_OBJECT_PROPERTY)},
            {"term":uri(term),"source_graph":uri(graph),"domain":uri("urn:test:Subject")},
            {"term":uri(term),"source_graph":uri(graph),"range":{"type":"bnode","value":"b1"}},
            {"term":uri(term),"source_graph":uri(graph),"label":literal("has value")},
            {"term":uri(term),"source_graph":uri(graph),"definition":literal("Relates a subject to a value.")},
            {"term":uri(term),"source_graph":uri(graph),"synonym":literal("value")}
        ]}});
        let inventory = BTreeMap::from([(
            graph.to_owned(),
            InventoryMember {
                path: "commons/Test.rdf".to_owned(),
                source: "official".to_owned(),
            },
        )]);
        let projected = project_terms(
            &rows,
            &[term.to_owned()],
            &inventory,
            "https://spec.edmcouncil.org/fibo/ontology/Primary/",
        )
        .unwrap();
        let term = &projected[0];
        assert_eq!(term["kind"], "object_property");
        assert_eq!(term["approved_inventory_member"], true);
        assert_eq!(term["official_source"], true);
        assert_eq!(term["source_kinds"][0], "official");
        assert_eq!(term["imported"], true);
        assert_eq!(term["definitions"][0], "Relates a subject to a value.");
        assert_eq!(term["aliases"][0], "value");
        assert_eq!(term["constraints"]["domains"][0]["iri"], "urn:test:Subject");
        assert_eq!(term["constraints"]["anonymous_range_present"], true);
        assert_eq!(term["constraints"]["complete"], false);
    }

    #[test]
    fn local_extension_terms_are_not_reported_as_official_fibo() {
        let graph = "https://ctxql.org/ontology/party-background/";
        let term = "https://ctxql.org/ontology/party-background/hasTaxResidence";
        let uri = |value: &str| json!({"type":"uri","value":value});
        let rows = json!({"results":{"bindings":[
            {"term":uri(term),"source_graph":uri(graph),"type":uri(OWL_OBJECT_PROPERTY)},
            {"term":uri(term),"source_graph":uri(graph),"range":uri("https://www.omg.org/spec/Commons/Locations/Country")}
        ]}});
        let inventory = BTreeMap::from([(
            graph.to_owned(),
            InventoryMember {
                path: "assets/party-background/party-background.rdf".to_owned(),
                source: "local_extension".to_owned(),
            },
        )]);
        let projected = project_terms(&rows, &[term.to_owned()], &inventory, graph).unwrap();
        assert_eq!(projected[0]["official_source"], false);
        assert_eq!(projected[0]["source_kinds"][0], "local_extension");
        assert_eq!(
            projected[0]["inventory_members"][0],
            "assets/party-background/party-background.rdf"
        );
    }

    #[test]
    fn v2_property_declarations_are_not_flattened() {
        let kinds = [
            (vec![OWL_OBJECT_PROPERTY], "object_property"),
            (vec![OWL_DATATYPE_PROPERTY], "datatype_property"),
            (vec![OWL_ANNOTATION_PROPERTY], "annotation_property"),
            (vec![RDF_PROPERTY], "generic_property"),
            (
                vec![OWL_OBJECT_PROPERTY, OWL_DATATYPE_PROPERTY],
                "conflicting_property",
            ),
        ];
        for (types, expected) in kinds {
            assert_eq!(
                term_kind(&types.into_iter().map(str::to_owned).collect()),
                Some(expected)
            );
        }
    }

    #[test]
    fn v2_identifier_expansion_and_exact_queries_are_deterministic() {
        assert_eq!(
            expand_compact_identifier("commons:DatesAndTimes/Date").as_deref(),
            Some("https://www.omg.org/spec/Commons/DatesAndTimes/Date")
        );
        assert_eq!(
            expand_compact_identifier("xsd:date").as_deref(),
            Some("http://www.w3.org/2001/XMLSchema#date")
        );
        assert!(expand_compact_identifier("unknown:Date").is_none());
        let types = BTreeSet::from([OWL_CLASS.to_owned()]);
        assert!(response_kind_matches(term_kind(&types), "class"));
    }

    #[test]
    fn v2_exact_resolution_never_selects_the_first_lexical_match() {
        let one = vec![json!({"iri":"urn:test:A"})];
        assert_eq!(
            resolution_projection(&one, false, false)["status"],
            "unique"
        );
        assert_eq!(
            resolution_projection(&one, false, false)["match"],
            "urn:test:A"
        );

        let ambiguous = vec![json!({"iri":"urn:test:A"}), json!({"iri":"urn:test:B"})];
        let resolution = resolution_projection(&ambiguous, false, false);
        assert_eq!(resolution["status"], "ambiguous");
        assert!(resolution["match"].is_null());
        assert_eq!(resolution["candidates"].as_array().unwrap().len(), 2);

        let truncated = resolution_projection(&one, false, true);
        assert_eq!(truncated["status"], "ambiguous");
        assert_eq!(truncated["complete"], false);
        assert_eq!(truncated["candidates_truncated"], true);
    }

    #[test]
    fn request_shape_and_limits_are_rejected_before_io() {
        let host = DirectFlureeOntologyToolHost {
            path: PathBuf::from("/does/not/exist"),
            ledger: "ctxql/poc:main".into(),
            t: 1,
            cid: "wrong".into(),
            inventory_root: "sha256:wrong".into(),
            source_quad_root: "sha256:wrong".into(),
            receipt: Arc::new(test_receipt()),
            capture: "sha256:wrong".into(),
            graphs: vec!["https://example.test/g".into()].into(),
            inventory_members: Arc::new(BTreeMap::from([(
                "https://example.test/g".into(),
                InventoryMember {
                    path: "fibo/Test.rdf".into(),
                    source: "official".into(),
                },
            )])),
            primary_graph: "https://example.test/g".into(),
            reader: Arc::new(OnceLock::new()),
            response_cache: Arc::new(Mutex::new(ResponseCache::default())),
            busy: Arc::new(AtomicBool::new(false)),
        };
        for request in [
            json!({"operation":"write","query":"x"}),
            json!({"operation":"search","query":"x","limit":21}),
            json!({"operation":"search","query":"x","extra":true}),
            json!({"operation":"describe","query":"https://e/x> } UNION { ?s ?p ?o"}),
        ] {
            assert_eq!(host.lookup(&request), Err(OntologyToolError::Denied));
        }
    }

    #[test]
    fn lookup_has_a_host_side_deadline() {
        let host = DirectFlureeOntologyToolHost {
            path: PathBuf::from("/does/not/exist"),
            ledger: "ctxql/poc:main".into(),
            t: 1,
            cid: "wrong".into(),
            inventory_root: "sha256:wrong".into(),
            source_quad_root: "sha256:wrong".into(),
            receipt: Arc::new(test_receipt()),
            capture: "sha256:wrong".into(),
            graphs: vec!["https://example.test/g".into()].into(),
            inventory_members: Arc::new(BTreeMap::from([(
                "https://example.test/g".into(),
                InventoryMember {
                    path: "fibo/Test.rdf".into(),
                    source: "official".into(),
                },
            )])),
            primary_graph: "https://example.test/g".into(),
            reader: Arc::new(OnceLock::new()),
            response_cache: Arc::new(Mutex::new(ResponseCache::default())),
            busy: Arc::new(AtomicBool::new(false)),
        };
        let result = run_with_deadline(host.clone(), |_| async {
            tokio::time::sleep(QUERY_DEADLINE + Duration::from_secs(2)).await;
            Ok(())
        });
        assert_eq!(result, Err("ontology query deadline exceeded".into()));
        assert!(!host.busy.load(Ordering::Acquire));

        let start = Instant::now();
        let result = run_with_budget(
            host.clone(),
            Arc::new(AtomicBool::new(false)),
            start + Duration::from_millis(30),
            |_| async { std::future::pending::<Result<(), String>>().await },
        );
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(!host.busy.load(Ordering::Acquire));

        let cancellation = Arc::new(AtomicBool::new(false));
        let cancel = cancellation.clone();
        let trigger = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            cancel.store(true, Ordering::Release);
        });
        let start = Instant::now();
        let result = run_with_budget(
            host.clone(),
            cancellation,
            start + QUERY_DEADLINE,
            |_| async { std::future::pending::<Result<(), String>>().await },
        );
        trigger.join().unwrap();
        assert_eq!(result, Err("ontology query cancelled".into()));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(!host.busy.load(Ordering::Acquire));
    }

    #[test]
    #[ignore = "requires the exact external party-background ontology cache"]
    fn party_background_direct_lookup_preserves_source_distinction() {
        let cache = PathBuf::from(
            std::env::var("CDB_PARTY_BACKGROUND_CACHE")
                .expect("CDB_PARTY_BACKGROUND_CACHE must name the exact external cache"),
        );
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("ontology");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let receipt = runtime
            .block_on(
                cdb_backend_fluree::official_bootstrap::bootstrap_party_background(&cache, &output),
            )
            .unwrap();
        std::fs::write(
            output.join("bootstrap.json"),
            serde_json::to_vec_pretty(&receipt).unwrap(),
        )
        .unwrap();
        let host = DirectFlureeOntologyToolHost::from_bootstrap(&output).unwrap();
        for (iri, official_source, source_kind) in [
            (
                "https://ctxql.org/ontology/party-background/hasTaxResidence",
                false,
                "local_extension",
            ),
            (
                "https://spec.edmcouncil.org/fibo/ontology/BE/LegalEntities/CorporateBodies/Corporation",
                true,
                "official",
            ),
        ] {
            let response = host
                .lookup(&json!({"operation":"resolve_exact","query":iri}))
                .unwrap();
            assert_eq!(response["resolution"]["status"], "unique");
            assert_eq!(response["terms"][0]["official_source"], official_source);
            assert_eq!(response["terms"][0]["source_kinds"][0], source_kind);
        }
    }

    #[test]
    #[ignore = "requires CDB_ONTOLOGY_TEST_PATH naming an explicit external ontology ledger"]
    fn real_raw_ledger_rejects_wrong_cid_and_supports_search_and_describe() {
        let configured = std::env::var("CDB_ONTOLOGY_TEST_PATH")
            .expect("CDB_ONTOLOGY_TEST_PATH must name the external ontology ledger");
        let path = Path::new(&configured);
        assert!(path.is_absolute());
        assert!(path.join("bootstrap.json").is_file());
        let host = DirectFlureeOntologyToolHost::from_bootstrap(path).unwrap();
        let search = host
            .lookup(&json!({"operation":"search","query":"commercial loan","limit":5}))
            .unwrap();
        let terms = search["terms"].as_array().unwrap();
        assert!(!terms.is_empty());
        let iri = terms[0]["iri"].as_str().unwrap();
        let described = host
            .lookup(&json!({"operation":"describe","query":iri,"limit":1}))
            .unwrap();
        assert_eq!(described["terms"][0]["iri"], iri);
        assert_eq!(described["terms"][0]["extraction_eligible"], true);
        assert_eq!(described["cid"], host.cid);
        for name in ["Borrower", "hasBorrower", "CreditAgreement"] {
            let exact = host
                .lookup(&json!({"operation":"resolve_exact","query":name,"limit":20}))
                .unwrap();
            assert_eq!(exact["terms"].as_array().unwrap().len(), 1);
            assert!(exact["terms"]
                .as_array()
                .unwrap()
                .iter()
                .any(|term| term["iri"]
                    .as_str()
                    .unwrap()
                    .ends_with(&format!("/Debt/{name}"))));
            let iri = format!(
                "https://spec.edmcouncil.org/fibo/ontology/FBC/DebtAndEquities/Debt/{name}"
            );
            let direct = host
                .lookup(&json!({"operation":"describe","query":iri,"limit":1}))
                .unwrap();
            assert_eq!(direct["terms"][0]["iri"], iri);
            assert!(!direct["terms"][0]["labels"].as_array().unwrap().is_empty());
        }

        let mut wrong = host.clone();
        wrong.cid = "bagaybqabogus".into();
        assert_eq!(
            wrong.lookup(&json!({"operation":"describe","query":iri,"limit":1})),
            Err(OntologyToolError::Denied)
        );
        let temp = tempfile::tempdir().unwrap();
        let mut forged: Value =
            serde_json::from_slice(&std::fs::read(path.join("bootstrap.json")).unwrap()).unwrap();
        forged["storage_path"] = json!(temp.path().to_string_lossy());
        forged["source_quad_root"] =
            json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        std::fs::write(temp.path().join("bootstrap.json"), forged.to_string()).unwrap();
        assert!(DirectFlureeOntologyToolHost::from_bootstrap(temp.path()).is_err());
    }
}
