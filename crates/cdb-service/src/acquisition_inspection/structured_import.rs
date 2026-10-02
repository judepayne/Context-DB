//! Authenticated admission of bounded administrator-authored structured claims.
//!
//! This is deliberately not a raw RDF or ledger-write API. Rust validates the
//! closed import format, verifies its vocabulary against the configured exact
//! ontology capture, and lowers claims through ordinary semantic admission.

use super::{denied, AcquisitionFence, AuthorizedAcquisition};
use crate::{
    acquisition::{AdministrativeAdmission, AdmissionContext, WaitPoint},
    auth,
    ontology_direct::DirectFlureeOntologyToolHost,
};
use cdb_backend_fluree::runs::ExternalPublicationFence;
use cdb_backend_fluree::{runs::Operation, semantic_policy::verify_semantic_authority_current};
use cdb_core::{
    claim::{CandidateClaim, TypedLiteral},
    contracts::SemanticProjectionSource,
    id::{AttemptId, BackendId, BundleId, ContentHash, ExtractionRunId, Iri, JobId},
    semantic_admission::{stable_acquisition_v2_claim_id, ValidatedSemanticBundle},
    snapshot::SnapshotRef,
    CanonicalValue as V, Error, ErrorKind, ExactNumber, Limits, Result, Timestamp,
};
use cdb_provider_pi::ontology_bridge::OntologyToolHost;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

struct ImportFence {
    authority: AcquisitionFence,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}
impl ExternalPublicationFence for ImportFence {
    fn check(&self) -> Result<()> {
        check_budget(&self.cancelled, self.deadline)?;
        self.authority.check()
    }
}
fn check_budget(cancelled: &AtomicBool, deadline: Instant) -> Result<()> {
    if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err(Error::new(
            ErrorKind::Deadline,
            "import cancelled or deadline exhausted",
        ));
    }
    Ok(())
}

const IMPORT_SCHEMA: &str = "ctxql-structured-claim-import/v1";
const CHECKPOINT_SCHEMA: &str = "ctxql-structured-claim-import-checkpoint/v1";
const CLAIMS_PER_BUNDLE: usize = 64;
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_CLASS: &str = "http://www.w3.org/2000/01/rdf-schema#Class";
const OWL_THING: &str = "http://www.w3.org/2002/07/owl#Thing";
const TYPE_RELATION: &str = "https://ctxql.example/acquisition/v2/TypeAssertionRelation";
const OBJECT_RELATION: &str = "https://ctxql.example/acquisition/v2/ObjectPropertyRelation";
const DATATYPE_RELATION: &str = "https://ctxql.example/acquisition/v2/DatatypePropertyRelation";
const CURATED: &str = "https://ctxql.example/import/v1/CuratedAssertion";

fn import_stage(error: Error, stage: &str) -> Error {
    Error::new(
        error.kind,
        format!("structured import {stage}: {}", error.message),
    )
}

fn seed_limits() -> Result<Limits> {
    Limits::new(
        16 * 1024 * 1024,
        64,
        1_000_000,
        100_000_000,
        16 * 1024 * 1024,
    )
}

pub(super) async fn admit(
    access: &std::sync::Arc<AuthorizedAcquisition>,
    token: &str,
    request: &[u8],
    cancelled: Arc<AtomicBool>,
) -> Result<V> {
    let deadline = Instant::now() + access.config.limits.deadline();
    check_budget(&cancelled, deadline)?;
    if request.len() > access.config.limits.max_body_bytes {
        return Err(Error::limit());
    }
    // Establish normal Admin authentication, authorization, and lease before
    // parsing untrusted bytes or entering any recovery-capable mutation path.
    let (_, _, initial_context, initial_lease, initial_basis) = access
        .authorize(token, Operation::Admin, auth::Operation::Admin)
        .await?;
    initial_lease.check().map_err(|_| denied())?;
    access
        .backend
        .require_operation(&initial_context, Operation::Admin)?;
    verify_semantic_authority_current(&access.semantic, &initial_basis)
        .await
        .map_err(|_| denied())?;

    let incoming = V::parse(request, seed_limits()?)?;
    let graph = decode_graph(&incoming)?;

    let raw_path = access
        .config
        .acquisition
        .as_ref()
        .and_then(|config| config.ontology_ledger_path.clone())
        .ok_or_else(|| Error::invalid("structured import ontology bootstrap required"))?;
    let vocabulary = graph.vocabulary.clone();
    // Opening/verifying Fluree and the synchronous lookup API both perform
    // native blocking work. Keep all of it off Tokio executor threads.
    let (provenance, ontology_root) = tokio::task::spawn_blocking(move || {
        let ontology = DirectFlureeOntologyToolHost::from_bootstrap(&raw_path)
            .map_err(|_| Error::invalid("structured import ontology bootstrap"))?;
        let provenance = ontology
            .provenance()
            .map_err(|_| Error::invalid("structured import ontology provenance"))?;
        verify_vocabulary(&ontology, &vocabulary)?;
        let root = ContentHash::of_bytes(&provenance.canonical_bytes(Limits::default())?);
        Ok::<_, Error>((provenance, root))
    })
    .await
    .map_err(|_| Error::new(ErrorKind::Backend, "import ontology worker stopped"))??;

    // The exact canonical graph is the retained WholeDocument curated source.
    // No model output or PDF automated-grounding representation is invented.
    check_budget(&cancelled, deadline)?;
    let source_bytes = incoming.canonical_bytes(seed_limits()?)?;
    let source_hash = ContentHash::of_bytes(&source_bytes);
    let identity = ContentHash::of_bytes(
        format!(
            "ctxql-structured-claim-import/v1\0{}\0{}",
            source_hash.as_str(),
            ontology_root.as_str()
        )
        .as_bytes(),
    );
    let suffix = &identity.as_str()[7..];
    let job = JobId::new(format!("urn:ctxql:job:structured-import:{suffix}"))?;
    let attempt = AttemptId::new(format!("urn:ctxql:attempt:structured-import:{suffix}"))?;

    // Ordinary admission commits are deliberately bounded. A single 496-claim
    // native commit exceeds the backend's fixed commit-verification budget.
    // Each batch freezes its exact current validation capture before preparing
    // that batch; restart consumes the immutable batch checkpoint.
    let claim_count = incoming.field("claims")?.as_array()?.len();
    let batch_count = claim_count.div_ceil(CLAIMS_PER_BUNDLE);
    let mut admissions = Vec::with_capacity(batch_count);
    let mut projections = Vec::with_capacity(batch_count);
    for index in 0..batch_count {
        check_budget(&cancelled, deadline)?;
        let batch_job = JobId::new(format!("{}:batch:{index}", job.as_str()))?;
        // Check current authorization before each protected checkpoint read,
        // including the first read after potentially lengthy ontology work.
        let (_, principal, context, lease, basis) = access
            .authorize(token, Operation::Admin, auth::Operation::Admin)
            .await?;
        let acquisition = access.acquisition.clone();
        let read_job = batch_job.clone();
        let frozen = access
            .backend
            .clone()
            .guarded_owned_action(
                principal,
                context,
                Operation::Admin,
                Box::new(ImportFence {
                    authority: AcquisitionFence {
                        lease,
                        semantic: access.semantic.clone(),
                        basis,
                    },
                    cancelled: cancelled.clone(),
                    deadline,
                }),
                move || async move { acquisition.work_value(&read_job, "structured_import").await },
            )
            .await?;
        let bundle = if let Some(frozen) = frozen {
            let mut decoded = decode_frozen(&frozen, &source_hash, &ontology_root)?;
            if decoded.len() != 1 {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "structured import checkpoint batch differs",
                ));
            }
            let bundle = decoded.remove(0);
            validate_frozen_batch(&incoming, &graph, &source_hash, &provenance, &bundle, index)?;
            bundle
        } else {
            let capture = SemanticProjectionSource::head(access.semantic.as_ref()).await?;
            let bundle = build_batch(&incoming, &graph, &source_hash, &provenance, capture, index)?;
            let frozen = V::object([
                ("schema".into(), V::string(CHECKPOINT_SCHEMA)),
                ("source_hash".into(), V::string(source_hash.as_str())),
                ("ontology_root".into(), V::string(ontology_root.as_str())),
                ("ontology".into(), provenance.clone()),
                (
                    "backend".into(),
                    V::string(bundle.validation_capture().backend().as_str()),
                ),
                ("bundles".into(), V::Array(vec![bundle.projection()])),
            ])?;
            let frozen_bytes = frozen.canonical_bytes(seed_limits()?)?;

            // Source objects and checkpoint links are durable mutations too.
            // Fence them without recursively entering Control from the callback.
            let (_, freeze_principal, freeze_context, freeze_lease, freeze_basis) = access
                .authorize(token, Operation::Admin, auth::Operation::Admin)
                .await?;
            let acquisition = access.acquisition.clone();
            let freeze_job = batch_job.clone();
            let expected_source = source_hash.clone();
            let freeze_source = source_bytes.clone();
            access
                .backend
                .clone()
                .guarded_owned_action(
                    freeze_principal,
                    freeze_context,
                    Operation::Admin,
                    Box::new(ImportFence {
                        authority: AcquisitionFence {
                            lease: freeze_lease,
                            semantic: access.semantic.clone(),
                            basis: freeze_basis,
                        },
                        cancelled: cancelled.clone(),
                        deadline,
                    }),
                    move || async move {
                        let stored = acquisition
                            .source_writer
                            .put(&freeze_source, acquisition.artifact_limit)
                            .await?;
                        if stored != expected_source {
                            return Err(Error::new(
                                ErrorKind::Conflict,
                                "curated graph source identity differs",
                            ));
                        }
                        let frozen_root = acquisition
                            .source_writer
                            .put(&frozen_bytes, acquisition.artifact_limit)
                            .await?;
                        acquisition
                            .work
                            .put(&freeze_job, "structured_import", &frozen_root)
                    },
                )
                .await
                .map_err(|error| import_stage(error, "checkpoint"))?;
            bundle
        };

        // Admission owns Control writes and must not execute recursively inside
        // guarded_owned_action. Reacquire current authority immediately first.

        let (_, principal, context, lease, basis) = access
            .authorize(token, Operation::Admin, auth::Operation::Admin)
            .await?;
        lease.check().map_err(|_| denied())?;
        access
            .backend
            .require_operation(&context, Operation::Admin)?;
        verify_semantic_authority_current(&access.semantic, &basis)
            .await
            .map_err(|_| denied())?;
        let outcome = access
            .acquisition
            .admit_foreground(
                batch_job,
                AttemptId::new(format!("{}:batch:{index}", attempt.as_str()))?,
                &bundle,
                source_hash.clone(),
                V::object([
                    (
                        "entities".into(),
                        V::integer(graph.entity_types.len() as u64),
                    ),
                    ("claims".into(), V::integer(bundle.claims().len() as u64)),
                ])?,
                recorded_now()?,
                if index + 1 == batch_count {
                    WaitPoint::Projected
                } else {
                    WaitPoint::Admitted
                },
                AdmissionContext::Administrative(Box::new(AdministrativeAdmission {
                    backend: access.backend.clone(),
                    principal,
                    context,
                    fence: Box::new(ImportFence {
                        authority: AcquisitionFence {
                            lease,
                            semantic: access.semantic.clone(),
                            basis,
                        },
                        cancelled: cancelled.clone(),
                        deadline,
                    }),
                })),
            )
            .await
            .map_err(|error| import_stage(error, "admission"))?;
        admissions.push(outcome.admission.projection());
        projections.push(
            outcome
                .projection
                .map(|receipt| receipt.projection())
                .unwrap_or(V::Null),
        );
    }

    // Receipts are disclosed only under fresh current authority. Internal
    // hashes and successfully committed earlier batches are not read tokens.
    let (_, principal, context, lease, basis) = access
        .authorize(token, Operation::Admin, auth::Operation::Admin)
        .await?;
    let response = V::object([
        (
            "schema".into(),
            V::string("ctxql-structured-claim-import-result/v1"),
        ),
        ("status".into(), V::string("admitted")),
        ("import_id".into(), V::string(job.as_str())),
        (
            "entity_count".into(),
            V::integer(graph.entity_types.len() as u64),
        ),
        ("claim_count".into(), V::integer(claim_count as u64)),
        ("admissions".into(), V::Array(admissions)),
        ("projections".into(), V::Array(projections)),
    ])?;
    access
        .backend
        .clone()
        .guarded_owned_action(
            principal,
            context,
            Operation::Admin,
            Box::new(ImportFence {
                authority: AcquisitionFence {
                    lease,
                    semantic: access.semantic.clone(),
                    basis,
                },
                cancelled,
                deadline,
            }),
            move || async move { Ok(response) },
        )
        .await
        .map_err(|error| import_stage(error, "release"))
}

fn recorded_now() -> Result<Timestamp> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::new(ErrorKind::Backend, "system clock precedes epoch"))?
        .as_millis();
    Timestamp::from_millis(i64::try_from(millis).map_err(|_| Error::limit())?)
}

#[derive(Clone)]
struct DecodedGraph {
    entity_types: BTreeMap<String, String>,
    vocabulary: BTreeMap<String, VocabularyKind>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum VocabularyKind {
    Class,
    ObjectProperty,
    DatatypeProperty,
    MixedProperty,
}
fn record_vocabulary(
    vocabulary: &mut BTreeMap<String, VocabularyKind>,
    iri: String,
    kind: VocabularyKind,
) -> Result<()> {
    if let Some(previous) = vocabulary.get(&iri) {
        if *previous == kind {
            return Ok(());
        }
        if *previous == VocabularyKind::Class || kind == VocabularyKind::Class {
            return Err(Error::invalid(
                "import term used as both class and property",
            ));
        }
        vocabulary.insert(iri, VocabularyKind::MixedProperty);
    } else {
        vocabulary.insert(iri, kind);
    }
    Ok(())
}
fn kind_matches(expected: VocabularyKind, kind: &str) -> bool {
    match expected {
        VocabularyKind::Class => kind == "class",
        VocabularyKind::ObjectProperty => {
            matches!(kind, "property" | "annotation_property" | "object_property")
        }
        VocabularyKind::DatatypeProperty => matches!(
            kind,
            "property" | "annotation_property" | "datatype_property"
        ),
        VocabularyKind::MixedProperty => matches!(kind, "property" | "annotation_property"),
    }
}

fn decode_graph(root: &V) -> Result<DecodedGraph> {
    root.closed(&["schema", "dataset", "sources", "entities", "claims"], &[])?;
    if root.field("schema")?.as_str()? != IMPORT_SCHEMA {
        return Err(Error::invalid("structured import schema"));
    }
    let dataset = root.field("dataset")?;
    dataset.closed(&["id", "version"], &[])?;
    Iri::new(checked_text(dataset.field("id")?, 2048)?)?;
    checked_text(dataset.field("version")?, 256)?;

    let sources = validate_sources(root.field("sources")?)?;
    let mut entity_types = BTreeMap::new();
    let mut explicitly_typed = BTreeSet::new();
    let mut vocabulary = BTreeMap::new();
    for entity in bounded(root.field("entities")?, 4096)? {
        entity.closed(&["id"], &["type"])?;
        let id = checked_text(entity.field("id")?, 2048)?;
        Iri::new(&id)?;
        let class = entity
            .as_object()?
            .get("type")
            .map(|value| checked_text(value, 2048))
            .transpose()?;
        if let Some(class) = &class {
            Iri::new(class)?;
            record_vocabulary(&mut vocabulary, class.clone(), VocabularyKind::Class)?;
            explicitly_typed.insert(id.clone());
        }
        if entity_types
            .insert(id, class.unwrap_or_else(|| OWL_THING.to_owned()))
            .is_some()
        {
            return Err(Error::invalid("duplicate structured import entity"));
        }
    }
    if entity_types.is_empty() {
        return Err(Error::invalid("empty structured import entities"));
    }

    let mut claim_ids = BTreeSet::new();
    for claim in bounded(root.field("claims")?, 10_000)? {
        claim.closed(&["id", "subject", "predicate", "object", "evidence"], &[])?;
        let id = checked_text(claim.field("id")?, 256)?;
        let subject = checked_text(claim.field("subject")?, 2048)?;
        let predicate = checked_text(claim.field("predicate")?, 2048)?;
        Iri::new(&predicate)?;
        if !claim_ids.insert(id) || !entity_types.contains_key(&subject) {
            return Err(Error::invalid("structured import claim identity"));
        }
        validate_evidence(claim.field("evidence")?, &sources)?;
        let object = claim.field("object")?;
        match object.field("type")?.as_str()? {
            "iri" => {
                object.closed(&["type", "value"], &[])?;
                let target = checked_text(object.field("value")?, 2048)?;
                if predicate == RDF_TYPE {
                    let declared = entity_types.get(&subject).map(String::as_str);
                    if explicitly_typed.contains(&subject) && declared != Some(target.as_str()) {
                        return Err(Error::invalid("structured import entity type differs"));
                    }
                    record_vocabulary(&mut vocabulary, target, VocabularyKind::Class)?;
                } else {
                    if !entity_types.contains_key(&target) {
                        return Err(Error::invalid("structured import dangling target"));
                    }
                    record_vocabulary(&mut vocabulary, predicate, VocabularyKind::ObjectProperty)?;
                }
            }
            "literal" => {
                object.closed(&["type", "value", "datatype"], &["language"])?;
                if predicate == RDF_TYPE {
                    return Err(Error::invalid("rdf:type requires an IRI object"));
                }
                if let V::String(value) = object.field("value")? {
                    if value.len() > 8192 || value.contains('\0') {
                        return Err(Error::limit());
                    }
                }
                TypedLiteral::from_value(&literal(object)?)?;
                let datatype = checked_text(object.field("datatype")?, 2048)?;
                let language = object.as_object()?.get("language");
                if datatype == "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString" {
                    checked_text(
                        language.ok_or_else(|| Error::invalid("language required"))?,
                        64,
                    )?;
                } else if language.is_some_and(|value| !matches!(value, V::Null)) {
                    return Err(Error::invalid("language requires rdf:langString"));
                }
                record_vocabulary(&mut vocabulary, predicate, VocabularyKind::DatatypeProperty)?;
            }
            _ => return Err(Error::invalid("structured import object type")),
        }
    }
    if claim_ids.is_empty() {
        return Err(Error::invalid("empty structured import claims"));
    }
    Ok(DecodedGraph {
        entity_types,
        vocabulary,
    })
}

fn validate_sources(value: &V) -> Result<BTreeSet<String>> {
    let values = bounded(value, 256)?;
    if values.is_empty() {
        return Err(Error::invalid("empty structured import sources"));
    }
    let mut result = BTreeSet::new();
    for source in values {
        source.closed(&["id", "kind", "uri", "version", "content_hash"], &[])?;
        let id = checked_text(source.field("id")?, 2048)?;
        checked_text(source.field("kind")?, 256)?;
        checked_text(source.field("uri")?, 4096)?;
        checked_text(source.field("version")?, 512)?;
        ContentHash::parse(source.field("content_hash")?.as_str()?)?;
        if !result.insert(id) {
            return Err(Error::invalid("duplicate structured import source"));
        }
    }
    Ok(result)
}

fn validate_evidence(value: &V, sources: &BTreeSet<String>) -> Result<()> {
    let evidence = bounded(value, 64)?;
    if evidence.is_empty() {
        return Err(Error::invalid("structured import claim lacks evidence"));
    }
    for item in evidence {
        item.closed(&["source", "selector"], &["quote", "note"])?;
        let source = checked_text(item.field("source")?, 2048)?;
        if !sources.contains(&source) {
            return Err(Error::invalid("structured import evidence source"));
        }
        let selector = item.field("selector")?;
        selector.closed(&["contract"], &["whole_document", "page", "utf8"])?;
        if selector.field("contract")?.as_str()? != "ctxql-evidence/v1" {
            return Err(Error::invalid("structured import evidence selector"));
        }
        let fields = selector.as_object()?;
        let valid = match (fields.get("whole_document"), fields.get("utf8")) {
            (Some(whole), None) => whole.as_bool()? && fields.len() == 2,
            (None, Some(span)) => {
                span.closed(&["start", "end"], &[])?;
                if let Some(page) = fields.get("page") {
                    if page.u64()? == 0 {
                        return Err(Error::invalid("structured import evidence page"));
                    }
                }
                span.field("start")?.u64()? <= span.field("end")?.u64()?
            }
            _ => false,
        };
        if !valid {
            return Err(Error::invalid("structured import evidence selector"));
        }
        if let Some(value) = item.as_object()?.get("quote") {
            checked_text(value, 16 * 1024)?;
        }
        if let Some(value) = item.as_object()?.get("note") {
            checked_text(value, 8192)?;
        }
    }
    Ok(())
}

fn verify_vocabulary(
    host: &DirectFlureeOntologyToolHost,
    vocabulary: &BTreeMap<String, VocabularyKind>,
) -> Result<()> {
    for (iri, expected) in vocabulary {
        let response = host
            .lookup(&json!({"operation":"describe", "query":iri, "limit":1}))
            .map_err(|_| Error::invalid("structured import ontology term unavailable"))?;
        let terms = response
            .get("terms")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| Error::invalid("structured import ontology response"))?;
        let term = terms
            .first()
            .filter(|_| terms.len() == 1)
            .ok_or_else(|| Error::invalid("structured import ontology term not unique"))?;
        let kind = term
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Error::invalid("structured import ontology declaration"))?;
        let kind_matches = kind_matches(*expected, kind);
        if term.get("iri").and_then(serde_json::Value::as_str) != Some(iri.as_str())
            || !kind_matches
            || term
                .get("extraction_eligible")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
            || term
                .get("approved_inventory_member")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
        {
            return Err(Error::invalid(
                "structured import ontology declaration differs",
            ));
        }
    }
    Ok(())
}

fn build_batch(
    seed: &V,
    graph: &DecodedGraph,
    source_hash: &ContentHash,
    ontology: &V,
    capture: SnapshotRef,
    index: usize,
) -> Result<ValidatedSemanticBundle> {
    let input_claims = seed.field("claims")?.as_array()?;
    let batch_count = input_claims.len().div_ceil(CLAIMS_PER_BUNDLE);
    if index >= batch_count {
        return Err(Error::invalid("structured import batch index"));
    }
    let start = index * CLAIMS_PER_BUNDLE;
    let end = input_claims.len().min(start + CLAIMS_PER_BUNDLE);
    let lineage = lineage(seed, source_hash)?;
    let mut claims = Vec::with_capacity(end - start);
    for claim in &input_claims[start..end] {
        let source_id = claim.field("id")?.as_str()?;
        let subject = claim.field("subject")?.as_str()?;
        let predicate = claim.field("predicate")?.as_str()?;
        let endpoint = claim.field("object")?;
        let endpoint_type = endpoint.field("type")?.as_str()?;
        let (object, relation_type, object_type) = match endpoint_type {
            "iri" if predicate == RDF_TYPE => (
                V::string(endpoint.field("value")?.as_str()?),
                TYPE_RELATION,
                RDF_CLASS.to_owned(),
            ),
            "iri" => {
                let target = endpoint.field("value")?.as_str()?;
                (
                    V::string(target),
                    OBJECT_RELATION,
                    graph
                        .entity_types
                        .get(target)
                        .cloned()
                        .unwrap_or_else(|| OWL_THING.to_owned()),
                )
            }
            "literal" => (
                literal(endpoint)?,
                DATATYPE_RELATION,
                endpoint.field("datatype")?.as_str()?.to_owned(),
            ),
            _ => return Err(Error::invalid("structured import object type")),
        };
        let subject_type = if predicate == RDF_TYPE {
            endpoint.field("value")?.as_str()?.to_owned()
        } else {
            graph
                .entity_types
                .get(subject)
                .cloned()
                .unwrap_or_else(|| OWL_THING.to_owned())
        };
        claims.push((
            source_id.to_owned(),
            make_claim(
                subject,
                predicate,
                object,
                relation_type,
                &subject_type,
                &object_type,
                lineage.clone(),
                claim.field("evidence")?.clone(),
                source_id,
            )?,
        ));
    }

    let identity = ContentHash::of_bytes(
        format!(
            "{}\0{}",
            source_hash.as_str(),
            ontology.field("capture")?.as_str()?
        )
        .as_bytes(),
    );
    let suffix = &identity.as_str()[7..];
    ValidatedSemanticBundle::new(
        BundleId::new(format!(
            "urn:ctxql:bundle:structured-import:{suffix}:batch:{index}"
        ))?,
        ExtractionRunId::new(format!(
            "urn:ctxql:extraction:curated-structured-import:{suffix}:batch:{index}"
        ))?,
        capture.clone(),
        V::object([
            (
                "schema".into(),
                V::string("ctxql-structured-claim-import-descriptor/v1"),
            ),
            ("source_hash".into(), V::string(source_hash.as_str())),
            ("source_kind".into(), V::string("curated_dataset")),
            (
                "source_selector".into(),
                V::object([
                    ("contract".into(), V::string("ctxql-evidence/v1")),
                    ("whole_document".into(), V::Bool(true)),
                ])?,
            ),
            ("dataset".into(), seed.field("dataset")?.clone()),
            ("ontology".into(), ontology.clone()),
            ("batch_index".into(), V::integer(index as u64)),
            ("batch_count".into(), V::integer(batch_count as u64)),
        ])?,
        claims,
        seed_limits()?,
    )
}

#[cfg(test)]
fn build_bundles(
    seed: &V,
    graph: &DecodedGraph,
    source_hash: &ContentHash,
    ontology: &V,
    capture: SnapshotRef,
) -> Result<Vec<ValidatedSemanticBundle>> {
    (0..seed
        .field("claims")?
        .as_array()?
        .len()
        .div_ceil(CLAIMS_PER_BUNDLE))
        .map(|index| build_batch(seed, graph, source_hash, ontology, capture.clone(), index))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn make_claim(
    subject: &str,
    predicate: &str,
    object: V,
    relation_type: &str,
    subject_type: &str,
    object_type: &str,
    lineage: V,
    evidence: V,
    component: &str,
) -> Result<CandidateClaim> {
    let mut value = V::object([
        (
            "claim_id".into(),
            V::string("urn:ctxql:claim:v2:placeholder"),
        ),
        ("subject_id".into(), V::string(subject)),
        ("relation".into(), V::string(predicate)),
        ("object_id".into(), object),
        ("relation_type".into(), V::string(relation_type)),
        ("subject_type".into(), V::string(subject_type)),
        ("object_type".into(), V::string(object_type)),
        ("claim_type".into(), V::string(CURATED)),
        ("confidence".into(), V::Number(ExactNumber::from_u64(1))),
        (
            "grounding_level".into(),
            V::string("source_lineage_available"),
        ),
        ("lineage".into(), lineage),
        (
            "ext".into(),
            V::object([
                (
                    "ctxql.acquisition.v2/claim_identity".into(),
                    V::string("stable-component/v1"),
                ),
                (
                    "ctxql.acquisition.v2/component_ref".into(),
                    V::string(format!("curated-structured-import:{component}")),
                ),
                (
                    "ctxql.structured-import/v1".into(),
                    V::object([
                        ("provenance".into(), V::string("curated_dataset")),
                        // The exact citation array remains in the immutable
                        // import object. Bind it by claim-local identity and
                        // hash rather than copying it into every ledger claim.
                        ("evidence_ref".into(), V::string(component)),
                        (
                            "evidence_root".into(),
                            V::string(
                                ContentHash::of_bytes(&evidence.canonical_bytes(seed_limits()?)?)
                                    .as_str(),
                            ),
                        ),
                    ])?,
                ),
            ])?,
        ),
    ])?;
    let provisional = CandidateClaim::from_value(&value)?;
    let id = stable_acquisition_v2_claim_id(&provisional, Limits::default())?;
    let V::Object(fields) = &mut value else {
        unreachable!()
    };
    fields.insert("claim_id".into(), V::string(id.as_str()));
    CandidateClaim::from_value(&value)
}

fn lineage(import: &V, source_hash: &ContentHash) -> Result<V> {
    // Only the exact retained import is verified and available locally. External
    // citations remain curator-declared data inside it, not verified sources or
    // whole-document capabilities. Binding this hash also separates datasets.
    let sources = vec![V::object([
        (
            "source_id".into(),
            import.field("dataset")?.field("id")?.clone(),
        ),
        ("kind".into(), V::string("ctxql.source.curated-dataset")),
        ("uri".into(), import.field("dataset")?.field("id")?.clone()),
        ("version".into(), V::string(source_hash.as_str())),
        ("content_hash".into(), V::string(source_hash.as_str())),
        (
            "selectors".into(),
            V::object([
                ("contract".into(), V::string("ctxql-evidence/v1")),
                ("whole_document".into(), V::Bool(true)),
            ])?,
        ),
    ])?];
    V::object([
        ("schema".into(), V::string("ctxql.lineage.v1")),
        ("sources".into(), V::Array(sources)),
    ])
}

fn literal(endpoint: &V) -> Result<V> {
    V::object([
        ("kind".into(), V::string("literal")),
        ("datatype".into(), endpoint.field("datatype")?.clone()),
        ("value".into(), endpoint.field("value")?.clone()),
        (
            "language".into(),
            endpoint
                .as_object()?
                .get("language")
                .cloned()
                .unwrap_or(V::Null),
        ),
    ])
}

fn checked_text(value: &V, max: usize) -> Result<String> {
    let text = value.as_str()?;
    if text.is_empty() || text.len() > max || text.contains('\0') {
        return Err(Error::invalid("structured import text"));
    }
    Ok(text.to_owned())
}

fn bounded(value: &V, max: usize) -> Result<&[V]> {
    let values = value.as_array()?;
    if values.len() > max {
        return Err(Error::limit());
    }
    Ok(values)
}

fn validate_frozen_batch(
    seed: &V,
    graph: &DecodedGraph,
    source_hash: &ContentHash,
    ontology: &V,
    bundle: &ValidatedSemanticBundle,
    index: usize,
) -> Result<()> {
    // A self-consistent stored bundle is not sufficient: bind it back to this
    // exact pinned graph and batch without replacing its frozen capture.
    let expected = build_batch(
        seed,
        graph,
        source_hash,
        ontology,
        bundle.validation_capture().clone(),
        index,
    )?;
    if expected.projection() != bundle.projection() {
        return Err(Error::new(
            ErrorKind::Conflict,
            "structured import checkpoint content differs",
        ));
    }
    Ok(())
}

fn decode_frozen(
    value: &V,
    source_hash: &ContentHash,
    ontology_root: &ContentHash,
) -> Result<Vec<ValidatedSemanticBundle>> {
    value.closed(
        &[
            "schema",
            "source_hash",
            "ontology_root",
            "ontology",
            "backend",
            "bundles",
        ],
        &[],
    )?;
    if value.field("schema")?.as_str()? != CHECKPOINT_SCHEMA
        || value.field("source_hash")?.as_str()? != source_hash.as_str()
        || value.field("ontology_root")?.as_str()? != ontology_root.as_str()
        || ContentHash::of_bytes(
            &value
                .field("ontology")?
                .canonical_bytes(Limits::default())?,
        ) != *ontology_root
    {
        return Err(Error::new(
            ErrorKind::Conflict,
            "structured import checkpoint differs",
        ));
    }
    let bundles = bounded(value.field("bundles")?, 32)?;
    if bundles.is_empty() {
        return Err(Error::invalid("empty structured import checkpoint"));
    }
    bundles
        .iter()
        .map(|bundle| {
            bundle.closed(
                &[
                    "schema",
                    "bundle_id",
                    "extraction_run",
                    "validation_capture",
                    "descriptor",
                    "descriptor_root",
                    "claims",
                    "payload_root",
                    "canonical_claim_root",
                    "admission_key",
                ],
                &[],
            )?;
            let claims = bundle
                .field("claims")?
                .as_array()?
                .iter()
                .map(|entry| {
                    entry.closed(&["role", "claim"], &[])?;
                    Ok((
                        entry.field("role")?.as_str()?.to_owned(),
                        CandidateClaim::from_value(entry.field("claim")?)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let decoded = ValidatedSemanticBundle::new(
                BundleId::new(bundle.field("bundle_id")?.as_str()?)?,
                ExtractionRunId::new(bundle.field("extraction_run")?.as_str()?)?,
                SnapshotRef::new(
                    BackendId::new(value.field("backend")?.as_str()?)?,
                    cdb_core::snapshot::GraphPin::from_value(bundle.field("validation_capture")?)?,
                ),
                bundle.field("descriptor")?.clone(),
                claims,
                seed_limits()?,
            )?;
            if decoded.projection() != *bundle {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "structured import frozen bundle differs",
                ));
            }
            Ok(decoded)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdb_core::id::{AuthorityId, GraphId, ResourceId, VersionId};
    use cdb_core::snapshot::GraphPin;

    fn input() -> V {
        V::parse(
            br#"{
              "schema":"ctxql-structured-claim-import/v1",
              "dataset":{"id":"urn:dataset:sample","version":"2026-10-01"},
              "sources":[{"id":"urn:source:registry","kind":"ctxql.source.curated-dataset","uri":"https://example.test/registry.csv","version":"1","content_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
              "entities":[
                {"id":"https://example.test/a","type":"https://example.test/Organization"},
                {"id":"https://example.test/b","type":"https://example.test/Organization"}
              ],
              "claims":[
                {"id":"name-a","subject":"https://example.test/a","predicate":"https://example.test/name","object":{"type":"literal","value":"Alpha","datatype":"http://www.w3.org/2001/XMLSchema#string"},"evidence":[{"source":"urn:source:registry","selector":{"contract":"ctxql-evidence/v1","whole_document":true},"note":"administrator-curated row"}]},
                {"id":"related","subject":"https://example.test/a","predicate":"https://example.test/related","object":{"type":"iri","value":"https://example.test/b"},"evidence":[{"source":"urn:source:registry","selector":{"contract":"ctxql-evidence/v1","whole_document":true}}]}
              ]
            }"#,
            seed_limits().unwrap(),
        )
        .unwrap()
    }

    fn capture() -> SnapshotRef {
        SnapshotRef::new(
            BackendId::new("semantic").unwrap(),
            GraphPin::new(
                AuthorityId::new("authority").unwrap(),
                GraphId::new("graph").unwrap(),
                VersionId::new("1").unwrap(),
                ResourceId::new("cid").unwrap(),
            ),
        )
    }

    fn modified_input(edit: impl FnOnce(&mut serde_json::Value)) -> V {
        let mut value: serde_json::Value =
            serde_json::from_slice(&input().canonical_bytes(seed_limits().unwrap()).unwrap())
                .unwrap();
        edit(&mut value);
        V::parse(&serde_json::to_vec(&value).unwrap(), seed_limits().unwrap()).unwrap()
    }

    #[test]
    fn an_entity_may_be_explicitly_untyped_without_asserting_owl_thing() {
        let request = modified_input(|input| {
            input["entities"][1].as_object_mut().unwrap().remove("type");
        });
        let graph = decode_graph(&request).unwrap();
        assert_eq!(graph.entity_types["https://example.test/b"], OWL_THING);
        assert!(!graph.vocabulary.contains_key(OWL_THING));
        let source =
            ContentHash::of_bytes(&request.canonical_bytes(seed_limits().unwrap()).unwrap());
        let ontology = V::object([("capture".into(), V::string("sha256:ontology"))]).unwrap();
        let bundles = build_bundles(&request, &graph, &source, &ontology, capture()).unwrap();
        assert_eq!(
            bundles
                .iter()
                .map(|bundle| bundle.claims().len())
                .sum::<usize>(),
            2
        );
    }

    #[test]
    fn optional_type_metadata_does_not_bypass_explicit_class_checks() {
        let request = |metadata: bool| {
            modified_input(|input| {
                if metadata {
                    input["entities"][0]["type"] = json!(OWL_THING);
                } else {
                    input["entities"][0].as_object_mut().unwrap().remove("type");
                }
                input["claims"][0]["predicate"] = json!(RDF_TYPE);
                input["claims"][0]["object"] = json!({"type":"iri","value":"urn:test:OtherClass"});
            })
        };
        assert!(decode_graph(&request(true)).is_err());
        let graph = decode_graph(&request(false)).unwrap();
        assert!(graph.vocabulary.get("urn:test:OtherClass") == Some(&VocabularyKind::Class));
        assert!(!graph.vocabulary.contains_key(OWL_THING));
    }

    #[test]
    fn rdf_type_used_as_a_class_is_not_exempt_from_ontology_checks() {
        let request = modified_input(|input| input["entities"][0]["type"] = json!(RDF_TYPE));
        let graph = decode_graph(&request).unwrap();
        assert!(graph.vocabulary.get(RDF_TYPE) == Some(&VocabularyKind::Class));
        assert!(!kind_matches(graph.vocabulary[RDF_TYPE], "property"));
    }

    #[test]
    fn maximum_size_import_builds_only_the_selected_batch() {
        let mut request = modified_input(|input| {
            let template = input["claims"][0].clone();
            input["claims"] = serde_json::Value::Array(
                (0..10_000)
                    .map(|index| {
                        let mut claim = template.clone();
                        claim["id"] = json!(format!("claim-{index}"));
                        claim
                    })
                    .collect(),
            );
        });
        let graph = decode_graph(&request).unwrap();
        // Deliberately poison a different batch AFTER full input validation.
        // Building/checking the final batch must not lower that earlier batch.
        let V::Object(root) = &mut request else {
            unreachable!()
        };
        let V::Array(claims) = root.get_mut("claims").unwrap() else {
            unreachable!()
        };
        claims[0] = V::Null;
        let source =
            ContentHash::of_bytes(&request.canonical_bytes(seed_limits().unwrap()).unwrap());
        let ontology = V::object([("capture".into(), V::string("sha256:ontology"))]).unwrap();
        let bundle = build_batch(&request, &graph, &source, &ontology, capture(), 156).unwrap();
        assert_eq!(bundle.claims().len(), 16);
        assert_eq!(
            bundle
                .projection()
                .field("descriptor")
                .unwrap()
                .field("batch_count")
                .unwrap()
                .u64()
                .unwrap(),
            157
        );
        validate_frozen_batch(&request, &graph, &source, &ontology, &bundle, 156).unwrap();
        assert!(build_batch(&request, &graph, &source, &ontology, capture(), 0).is_err());
        assert!(build_batch(&request, &graph, &source, &ontology, capture(), 157).is_err());
    }

    #[test]
    fn typed_values_are_checked_before_admission() {
        for (datatype, value) in [
            ("integer", json!(42)),
            ("decimal", json!(12.5)),
            ("boolean", json!(true)),
            ("string", json!("")),
            ("date", json!("2026-10-01")),
        ] {
            let request = modified_input(|input| {
                input["claims"][0]["object"]["datatype"] =
                    json!(format!("http://www.w3.org/2001/XMLSchema#{datatype}"));
                input["claims"][0]["object"]["value"] = value;
            });
            assert!(decode_graph(&request).is_ok(), "{datatype}");
        }
        for (datatype, value) in [
            ("integer", json!(1.5)),
            ("boolean", json!("true")),
            ("unsignedByte", json!(256)),
            ("date", json!("2026-02-30")),
        ] {
            let request = modified_input(|input| {
                input["claims"][0]["object"]["datatype"] =
                    json!(format!("http://www.w3.org/2001/XMLSchema#{datatype}"));
                input["claims"][0]["object"]["value"] = value;
            });
            assert!(decode_graph(&request).is_err(), "{datatype}");
        }
        assert!(decode_graph(&modified_input(|input| {
            input["claims"][0]["predicate"] = json!(RDF_TYPE);
        }))
        .is_err());
    }

    #[test]
    fn property_kinds_cannot_be_overwritten_or_misused() {
        assert!(!kind_matches(
            VocabularyKind::ObjectProperty,
            "datatype_property"
        ));
        assert!(!kind_matches(
            VocabularyKind::DatatypeProperty,
            "object_property"
        ));
        let mut terms = BTreeMap::new();
        record_vocabulary(&mut terms, "urn:p".into(), VocabularyKind::ObjectProperty).unwrap();
        record_vocabulary(&mut terms, "urn:p".into(), VocabularyKind::DatatypeProperty).unwrap();
        assert!(terms["urn:p"] == VocabularyKind::MixedProperty);
        assert!(record_vocabulary(&mut terms, "urn:p".into(), VocabularyKind::Class).is_err());
    }

    #[test]
    fn selectors_keep_explicit_utf8_units_and_reject_invalid_ranges() {
        for selector in [
            json!({"contract":"ctxql-evidence/v1", "utf8":{"start":0,"end":0}}),
            json!({"contract":"ctxql-evidence/v1", "utf8":{"start":0,"end":4}, "page":1}),
        ] {
            assert!(decode_graph(&modified_input(
                |input| input["claims"][0]["evidence"][0]["selector"] = selector
            ))
            .is_ok());
        }
        for selector in [
            json!({"contract":"ctxql-evidence/v1", "start":0,"end":4}),
            json!({"contract":"ctxql-evidence/v1", "utf8":{"start":4,"end":0}}),
            json!({"contract":"ctxql-evidence/v1", "utf8":{"start":0,"end":4}, "page":0}),
        ] {
            assert!(decode_graph(&modified_input(
                |input| input["claims"][0]["evidence"][0]["selector"] = selector
            ))
            .is_err());
        }
    }

    #[test]
    fn dataset_identity_is_bound_to_claims_and_retained_source() {
        let first = input();
        let second = modified_input(|input| input["dataset"]["id"] = json!("urn:dataset:other"));
        let ontology = V::object([("capture".into(), V::string("sha256:ontology"))]).unwrap();
        let bundles = |input: &V| {
            let hash =
                ContentHash::of_bytes(&input.canonical_bytes(seed_limits().unwrap()).unwrap());
            let lineage = lineage(input, &hash).unwrap();
            assert_eq!(
                lineage.field("sources").unwrap().as_array().unwrap()[0]
                    .field("content_hash")
                    .unwrap()
                    .as_str()
                    .unwrap(),
                hash.as_str()
            );
            build_bundles(
                input,
                &decode_graph(input).unwrap(),
                &hash,
                &ontology,
                capture(),
            )
            .unwrap()
        };
        assert_ne!(
            bundles(&first)[0].claims()[0].projection(),
            bundles(&second)[0].claims()[0].projection()
        );
    }

    #[test]
    fn cancelled_or_expired_imports_fail_closed() {
        assert!(check_budget(
            &AtomicBool::new(true),
            Instant::now() + std::time::Duration::from_secs(60)
        )
        .is_err());
        assert!(check_budget(&AtomicBool::new(false), Instant::now()).is_err());
    }

    #[test]
    fn two_different_generic_datasets_decode() {
        let first = input();
        let first_graph = decode_graph(&first).unwrap();
        assert_eq!(first_graph.entity_types.len(), 2);
        let mut second = first;
        let V::Object(root) = &mut second else {
            unreachable!()
        };
        let V::Object(dataset) = root.get_mut("dataset").unwrap() else {
            unreachable!()
        };
        dataset.insert("id".into(), V::string("urn:dataset:another"));
        assert!(decode_graph(&second).is_ok());
    }

    #[test]
    fn rejects_dangling_entities_sources_and_implicit_literal_datatypes() {
        let base = input();
        let mut dangling = base.clone();
        let V::Object(root) = &mut dangling else {
            unreachable!()
        };
        let V::Array(claims) = root.get_mut("claims").unwrap() else {
            unreachable!()
        };
        let V::Object(claim) = &mut claims[1] else {
            unreachable!()
        };
        let V::Object(object) = claim.get_mut("object").unwrap() else {
            unreachable!()
        };
        object.insert("value".into(), V::string("https://example.test/missing"));
        assert!(decode_graph(&dangling).is_err());

        let mut bad_source = base.clone();
        let V::Object(root) = &mut bad_source else {
            unreachable!()
        };
        let V::Array(claims) = root.get_mut("claims").unwrap() else {
            unreachable!()
        };
        let V::Object(claim) = &mut claims[0] else {
            unreachable!()
        };
        let V::Array(evidence) = claim.get_mut("evidence").unwrap() else {
            unreachable!()
        };
        let V::Object(item) = &mut evidence[0] else {
            unreachable!()
        };
        item.insert("source".into(), V::string("urn:source:missing"));
        assert!(decode_graph(&bad_source).is_err());

        let mut no_datatype = base;
        let V::Object(root) = &mut no_datatype else {
            unreachable!()
        };
        let V::Array(claims) = root.get_mut("claims").unwrap() else {
            unreachable!()
        };
        let V::Object(claim) = &mut claims[0] else {
            unreachable!()
        };
        let V::Object(object) = claim.get_mut("object").unwrap() else {
            unreachable!()
        };
        object.remove("datatype");
        assert!(decode_graph(&no_datatype).is_err());
    }

    #[test]
    fn lowering_is_stable_and_binds_evidence_and_declared_sources() {
        let import = input();
        let graph = decode_graph(&import).unwrap();
        let bytes = import.canonical_bytes(seed_limits().unwrap()).unwrap();
        let source_hash = ContentHash::of_bytes(&bytes);
        let ontology = V::object([("capture".into(), V::string("sha256:ontology"))]).unwrap();
        let first = build_bundles(&import, &graph, &source_hash, &ontology, capture()).unwrap();
        let second = build_bundles(&import, &graph, &source_hash, &ontology, capture()).unwrap();
        assert_eq!(
            first
                .iter()
                .map(ValidatedSemanticBundle::projection)
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(ValidatedSemanticBundle::projection)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            first
                .iter()
                .map(|bundle| bundle.claims().len())
                .sum::<usize>(),
            2
        );
        assert_eq!(first[0].claims()[0].lineage().sources().len(), 1);
    }
}
