//! Trusted, administrator-only admission of the pinned curated party graph.
//!
//! This is deliberately not a general RDF/triple admission API. The caller's
//! canonical value must equal the graph compiled into this binary. Rust then
//! verifies the vocabulary against the configured exact raw ontology capture
//! and lowers that graph through the ordinary claim-centric admission path.

use super::{denied, AcquisitionFence, AuthorizedAcquisition};
use crate::{
    acquisition::{AdministrativeAdmission, AdmissionContext, WaitPoint},
    auth,
    ontology_direct::DirectFlureeOntologyToolHost,
};
use cdb_backend_fluree::{runs::Operation, semantic_policy::verify_semantic_authority_current};
use cdb_core::{
    claim::CandidateClaim,
    contracts::SemanticProjectionSource,
    id::{AttemptId, BackendId, BundleId, ContentHash, ExtractionRunId, JobId},
    semantic_admission::{stable_acquisition_v2_claim_id, ValidatedSemanticBundle},
    snapshot::SnapshotRef,
    CanonicalValue as V, Error, ErrorKind, ExactNumber, Limits, Result, Timestamp,
};
use cdb_provider_pi::ontology_bridge::OntologyToolHost;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

const PINNED_SEED: &[u8] =
    include_bytes!("../../../../fixtures/quickstart/party-background/seed.json");
const SEED_SCHEMA: &str = "ctxql-party-background-seed/v1";
const CHECKPOINT_SCHEMA: &str = "ctxql-party-background-frozen-seed/v3";
const CLAIMS_PER_BUNDLE: usize = 64;
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_CLASS: &str = "http://www.w3.org/2000/01/rdf-schema#Class";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const OWL_THING: &str = "http://www.w3.org/2002/07/owl#Thing";
const TYPE_RELATION: &str = "https://ctxql.example/acquisition/v2/TypeAssertionRelation";
const OBJECT_RELATION: &str = "https://ctxql.example/acquisition/v2/ObjectPropertyRelation";
const DATATYPE_RELATION: &str = "https://ctxql.example/acquisition/v2/DatatypePropertyRelation";
const ACCEPTED: &str = "https://ctxql.example/acquisition/v2/AcceptedExtractionClaim";

fn party_stage(error: Error, stage: &str) -> Error {
    Error::new(error.kind, format!("party seed {stage}: {}", error.message))
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
) -> Result<V> {
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

    let incoming = V::parse(request, Limits::default())?;
    let pinned = pinned_seed()?;
    if incoming != pinned {
        return Err(Error::new(
            ErrorKind::Denied,
            "party seed differs from the pinned graph",
        ));
    }
    let graph = decode_graph(&incoming)?;

    let raw_path = access
        .config
        .acquisition
        .as_ref()
        .and_then(|config| config.ontology_ledger_path.clone())
        .ok_or_else(|| Error::invalid("party-background ontology bootstrap required"))?;
    let vocabulary = graph.vocabulary.clone();
    // Opening/verifying Fluree and the synchronous lookup API both perform
    // native blocking work. Keep all of it off Tokio executor threads.
    let (provenance, ontology_root) = tokio::task::spawn_blocking(move || {
        let ontology = DirectFlureeOntologyToolHost::from_bootstrap(&raw_path)
            .map_err(|_| Error::invalid("party-background ontology bootstrap"))?;
        let provenance = ontology
            .provenance()
            .map_err(|_| Error::invalid("party-background ontology provenance"))?;
        verify_vocabulary(&ontology, &vocabulary)?;
        let root = ContentHash::of_bytes(&provenance.canonical_bytes(Limits::default())?);
        Ok::<_, Error>((provenance, root))
    })
    .await
    .map_err(|_| Error::new(ErrorKind::Backend, "party ontology worker stopped"))??;

    // The exact canonical graph is the retained WholeDocument curated source.
    // No model output or PDF automated-grounding representation is invented.
    let source_bytes = incoming.canonical_bytes(Limits::default())?;
    let source_hash = ContentHash::of_bytes(&source_bytes);
    let identity = ContentHash::of_bytes(
        format!(
            "ctxql-party-background-seed/v2\0{}\0{}",
            source_hash.as_str(),
            ontology_root.as_str()
        )
        .as_bytes(),
    );
    let suffix = &identity.as_str()[7..];
    let job = JobId::new(format!("urn:ctxql:job:party-background:{suffix}"))?;
    let attempt = AttemptId::new(format!("urn:ctxql:attempt:party-background:{suffix}"))?;

    // Ordinary admission commits are deliberately bounded. A single 496-claim
    // native commit exceeds the backend's fixed commit-verification budget.
    // Each batch freezes its exact current validation capture before preparing
    // that batch; restart consumes the immutable batch checkpoint.
    let claim_count = incoming.field("claims")?.as_array()?.len();
    let batch_count = claim_count.div_ceil(CLAIMS_PER_BUNDLE);
    let mut admissions = Vec::with_capacity(batch_count);
    let mut projections = Vec::with_capacity(batch_count);
    for index in 0..batch_count {
        let batch_job = JobId::new(format!("{}:batch:{index}", job.as_str()))?;
        let bundle = if let Some(frozen) = access
            .acquisition
            .work_value(&batch_job, "party_seed")
            .await?
        {
            let mut decoded = decode_frozen(&frozen, &source_hash, &ontology_root)?;
            if decoded.len() != 1 {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "party seed checkpoint batch differs",
                ));
            }
            let bundle = decoded.remove(0);
            validate_frozen_batch(&incoming, &graph, &source_hash, &provenance, &bundle, index)?;
            bundle
        } else {
            let capture = SemanticProjectionSource::head(access.semantic.as_ref()).await?;
            let mut built = build_bundles(&incoming, &graph, &source_hash, &provenance, capture)?;
            let bundle = built.remove(index);
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
                    Box::new(AcquisitionFence {
                        lease: freeze_lease,
                        semantic: access.semantic.clone(),
                        basis: freeze_basis,
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
                            .put(&freeze_job, "party_seed", &frozen_root)
                    },
                )
                .await
                .map_err(|error| party_stage(error, "checkpoint"))?;
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
                    fence: Box::new(AcquisitionFence {
                        lease,
                        semantic: access.semantic.clone(),
                        basis,
                    }),
                })),
            )
            .await
            .map_err(|error| party_stage(error, "admission"))?;
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
            V::string("ctxql-party-background-seed-result/v1"),
        ),
        ("status".into(), V::string("admitted")),
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
            Box::new(AcquisitionFence {
                lease,
                semantic: access.semantic.clone(),
                basis,
            }),
            move || async move { Ok(response) },
        )
        .await
        .map_err(|error| party_stage(error, "release"))
}

fn recorded_now() -> Result<Timestamp> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::new(ErrorKind::Backend, "system clock precedes epoch"))?
        .as_millis();
    Timestamp::from_millis(i64::try_from(millis).map_err(|_| Error::limit())?)
}

fn pinned_seed() -> Result<V> {
    V::parse(PINNED_SEED, Limits::default())
        .map_err(|_| Error::new(ErrorKind::Backend, "compiled party seed is invalid"))
}

#[derive(Clone)]
struct DecodedGraph {
    entity_types: BTreeMap<String, String>,
    vocabulary: BTreeMap<String, VocabularyKind>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum VocabularyKind {
    Class,
    Property,
}

fn decode_graph(root: &V) -> Result<DecodedGraph> {
    root.closed(
        &[
            "schema",
            "version",
            "namespace",
            "source_documents",
            "entities",
            "claims",
            "excluded_references",
        ],
        &[],
    )?;
    if root.field("schema")?.as_str()? != SEED_SCHEMA
        || root.field("namespace")?.as_str()? != "https://ctxql.org/ontology/party-background/"
    {
        return Err(Error::invalid("party seed identity"));
    }
    checked_text(root.field("version")?, 128)?;
    let documents = validate_documents(root.field("source_documents")?)?;
    validate_exclusions(root.field("excluded_references")?, &documents)?;

    let mut kinds = BTreeMap::new();
    for entity in bounded(root.field("entities")?, 1024)? {
        entity.closed(&["id", "kind"], &[])?;
        let id = checked_text(entity.field("id")?, 2048)?;
        let kind = checked_text(entity.field("kind")?, 64)?;
        if !matches!(
            kind.as_str(),
            "address"
                | "country"
                | "identification_scheme"
                | "identifier"
                | "jurisdiction"
                | "jurisdiction_region"
                | "legal_entity"
                | "organization"
                | "public_body"
                | "trust"
        ) || kinds.insert(id, kind).is_some()
        {
            return Err(Error::invalid("party seed entity"));
        }
    }
    if kinds.is_empty() {
        return Err(Error::invalid("empty party seed graph"));
    }

    let mut explicit_types = BTreeMap::new();
    let mut claim_ids = BTreeSet::new();
    let mut vocabulary = BTreeMap::new();
    for claim in bounded(root.field("claims")?, 10_000)? {
        claim.closed(&["id", "subject", "predicate", "object", "evidence"], &[])?;
        let id = checked_text(claim.field("id")?, 256)?;
        let subject = checked_text(claim.field("subject")?, 2048)?;
        let predicate = checked_text(claim.field("predicate")?, 2048)?;
        if !claim_ids.insert(id) || !kinds.contains_key(&subject) {
            return Err(Error::invalid("party seed claim identity"));
        }
        validate_evidence(claim.field("evidence")?, &documents)?;
        let object = claim.field("object")?;
        let object_fields = object.as_object()?;
        match object.field("type")?.as_str()? {
            "iri" => {
                object.closed(&["type", "value"], &[])?;
                let target = checked_text(object.field("value")?, 2048)?;
                if predicate == RDF_TYPE {
                    vocabulary.insert(target.clone(), VocabularyKind::Class);
                    if explicit_types.insert(subject, target).is_some() {
                        return Err(Error::invalid("multiple explicit party seed types"));
                    }
                } else {
                    if !kinds.contains_key(&target) {
                        return Err(Error::invalid("party seed dangling target"));
                    }
                    vocabulary.insert(predicate, VocabularyKind::Property);
                }
            }
            "literal" => {
                object.closed(&["type", "value", "datatype"], &[])?;
                checked_text(object.field("value")?, 8192)?;
                if object.field("datatype")?.as_str()? != XSD_STRING {
                    return Err(Error::invalid("party seed literal datatype"));
                }
                vocabulary.insert(predicate, VocabularyKind::Property);
            }
            _ => return Err(Error::invalid("party seed object type")),
        }
        if object_fields.is_empty() {
            return Err(Error::invalid("party seed object"));
        }
    }
    if claim_ids.is_empty() {
        return Err(Error::invalid("empty party seed claims"));
    }
    vocabulary.remove(RDF_TYPE);

    let entity_types = kinds
        .into_keys()
        .map(|id| {
            let class = explicit_types
                .get(&id)
                .cloned()
                .unwrap_or_else(|| OWL_THING.to_owned());
            (id, class)
        })
        .collect();
    Ok(DecodedGraph {
        entity_types,
        vocabulary,
    })
}

fn validate_documents(value: &V) -> Result<BTreeMap<String, ContentHash>> {
    let documents = bounded(value, 32)?;
    if documents.is_empty() {
        return Err(Error::invalid("empty party seed sources"));
    }
    let mut result = BTreeMap::new();
    for document in documents {
        document.closed(&["pdf", "sha256", "pages", "page_text"], &[])?;
        let pdf = checked_text(document.field("pdf")?, 512)?;
        let digest = ContentHash::parse(format!("sha256:{}", document.field("sha256")?.as_str()?))?;
        checked_text(document.field("page_text")?, 512)?;
        if document.field("pages")?.u64()? == 0 || result.insert(pdf, digest).is_some() {
            return Err(Error::invalid("party seed source document"));
        }
    }
    Ok(result)
}

fn validate_exclusions(value: &V, documents: &BTreeMap<String, ContentHash>) -> Result<()> {
    for exclusion in bounded(value, 256)? {
        // Exclusions are retained as part of the exact source. Validate their
        // source citation without interpreting them as business assertions.
        let object = exclusion.as_object()?;
        if object.is_empty() {
            return Err(Error::invalid("party seed excluded reference"));
        }
        if let Some(evidence) = object.get("evidence") {
            validate_evidence_item(evidence, documents)?;
        }
    }
    Ok(())
}

fn validate_evidence(value: &V, documents: &BTreeMap<String, ContentHash>) -> Result<()> {
    let evidence = bounded(value, 64)?;
    if evidence.is_empty() {
        return Err(Error::invalid("party seed claim lacks evidence"));
    }
    for item in evidence {
        validate_evidence_item(item, documents)?;
    }
    Ok(())
}

fn validate_evidence_item(value: &V, documents: &BTreeMap<String, ContentHash>) -> Result<()> {
    value.closed(&["pdf", "sha256", "page", "quote", "interpretation"], &[])?;
    let pdf = checked_text(value.field("pdf")?, 512)?;
    let digest = ContentHash::parse(format!("sha256:{}", value.field("sha256")?.as_str()?))?;
    if documents.get(&pdf) != Some(&digest) || value.field("page")?.u64()? == 0 {
        return Err(Error::invalid("party seed evidence source"));
    }
    checked_text(value.field("quote")?, 16 * 1024)?;
    checked_text(value.field("interpretation")?, 8192)?;
    Ok(())
}

fn verify_vocabulary(
    host: &DirectFlureeOntologyToolHost,
    vocabulary: &BTreeMap<String, VocabularyKind>,
) -> Result<()> {
    for (iri, expected) in vocabulary {
        let response = host
            .lookup(&json!({"operation":"describe", "query":iri, "limit":1}))
            .map_err(|_| Error::invalid("party seed ontology term unavailable"))?;
        let terms = response
            .get("terms")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| Error::invalid("party seed ontology response"))?;
        let term = terms
            .first()
            .filter(|_| terms.len() == 1)
            .ok_or_else(|| Error::invalid("party seed ontology term not unique"))?;
        let kind = term
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Error::invalid("party seed ontology declaration"))?;
        let kind_matches = match expected {
            VocabularyKind::Class => kind == "class",
            VocabularyKind::Property => kind == "property" || kind.ends_with("_property"),
        };
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
            return Err(Error::invalid("party seed ontology declaration differs"));
        }
    }
    Ok(())
}

fn build_bundles(
    seed: &V,
    graph: &DecodedGraph,
    source_hash: &ContentHash,
    ontology: &V,
    capture: SnapshotRef,
) -> Result<Vec<ValidatedSemanticBundle>> {
    let lineage = lineage(source_hash)?;
    let mut claims = Vec::new();
    for claim in seed.field("claims")?.as_array()? {
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
                literal(endpoint.field("value")?.as_str()?)?,
                DATATYPE_RELATION,
                endpoint.field("datatype")?.as_str()?.to_owned(),
            ),
            _ => return Err(Error::invalid("party seed object type")),
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
    let batch_count = claims.len().div_ceil(CLAIMS_PER_BUNDLE);
    claims
        .chunks(CLAIMS_PER_BUNDLE)
        .enumerate()
        .map(|(index, claims)| {
            ValidatedSemanticBundle::new(
                BundleId::new(format!(
                    "urn:ctxql:bundle:party-background:{suffix}:batch:{index}"
                ))?,
                ExtractionRunId::new(format!(
                    "urn:ctxql:extraction:curated-party-background:{suffix}:batch:{index}"
                ))?,
                capture.clone(),
                V::object([
                    (
                        "schema".into(),
                        V::string("ctxql-curated-party-background-descriptor/v3"),
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
                    ("seed_version".into(), seed.field("version")?.clone()),
                    ("ontology".into(), ontology.clone()),
                    ("batch_index".into(), V::integer(index as u64)),
                    ("batch_count".into(), V::integer(batch_count as u64)),
                ])?,
                claims.to_vec(),
                seed_limits()?,
            )
        })
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
        ("claim_type".into(), V::string(ACCEPTED)),
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
                    V::string(format!("curated-party-background:{component}")),
                ),
                (
                    "ctxql.curated.party-background/v2".into(),
                    V::object([
                        ("provenance".into(), V::string("curated_dataset")),
                        // The complete citation array remains in the immutable
                        // pinned source object. Bind it by its source claim ID
                        // instead of copying large quotes into every admitted
                        // claim and exhausting ordinary admission budgets.
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

fn lineage(source_hash: &ContentHash) -> Result<V> {
    V::object([
        ("schema".into(), V::string("ctxql.lineage.v1")),
        (
            "sources".into(),
            V::Array(vec![V::object([
                (
                    "source_id".into(),
                    V::string("urn:ctxql:source:curated-party-background-graph"),
                ),
                ("kind".into(), V::string("ctxql.source.curated-dataset")),
                (
                    "uri".into(),
                    V::string("https://ctxql.org/datasets/party-background/seed.json"),
                ),
                ("version".into(), V::string(source_hash.as_str())),
                ("content_hash".into(), V::string(source_hash.as_str())),
                (
                    "selectors".into(),
                    V::object([
                        ("contract".into(), V::string("ctxql-evidence/v1")),
                        ("whole_document".into(), V::Bool(true)),
                    ])?,
                ),
            ])?]),
        ),
    ])
}

fn literal(value: &str) -> Result<V> {
    V::object([
        ("kind".into(), V::string("literal")),
        ("datatype".into(), V::string(XSD_STRING)),
        ("value".into(), V::string(value)),
        ("language".into(), V::Null),
    ])
}

fn checked_text(value: &V, max: usize) -> Result<String> {
    let text = value.as_str()?;
    if text.is_empty() || text.len() > max || text.contains('\0') {
        return Err(Error::invalid("party seed text"));
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
    let expected = build_bundles(
        seed,
        graph,
        source_hash,
        ontology,
        bundle.validation_capture().clone(),
    )?;
    if expected.get(index).map(ValidatedSemanticBundle::projection) != Some(bundle.projection()) {
        return Err(Error::new(
            ErrorKind::Conflict,
            "party seed checkpoint content differs",
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
            "party seed checkpoint differs",
        ));
    }
    let bundles = bounded(value.field("bundles")?, 32)?;
    if bundles.is_empty() {
        return Err(Error::invalid("empty party seed checkpoint"));
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
                    "party seed frozen bundle differs",
                ));
            }
            Ok(decoded)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires CDB_PARTY_BACKGROUND_ONTOLOGY exact native bootstrap"]
    fn pinned_graph_vocabulary_exists_in_exact_party_background_bootstrap() {
        let path = std::env::var_os("CDB_PARTY_BACKGROUND_ONTOLOGY")
            .expect("CDB_PARTY_BACKGROUND_ONTOLOGY");
        let host =
            DirectFlureeOntologyToolHost::from_bootstrap(std::path::Path::new(&path)).unwrap();
        let graph = decode_graph(&pinned_seed().unwrap()).unwrap();
        verify_vocabulary(&host, &graph.vocabulary).unwrap();
    }

    #[test]
    fn compiled_seed_decodes_with_expected_graph_semantics() {
        let seed = pinned_seed().unwrap();
        let graph = decode_graph(&seed).unwrap();
        assert_eq!(graph.entity_types.len(), 186);
        assert_eq!(seed.field("claims").unwrap().as_array().unwrap().len(), 496);
        assert_eq!(
            graph.entity_types["https://ctxql.org/ontology/party-background/place/delaware"],
            "https://www.omg.org/spec/Commons/Locations/GeographicRegion"
        );
        assert_eq!(
            graph.entity_types["https://ctxql.org/ontology/party-background/address/p000-dignity-plc/1"],
            "https://spec.edmcouncil.org/fibo/ontology/FND/Places/Addresses/ConventionalStreetAddress"
        );
        assert!(graph
            .vocabulary
            .contains_key("https://www.omg.org/spec/Commons/Organizations/OrganizationIdentifier"));
        assert!(graph
            .vocabulary
            .contains_key("https://www.omg.org/spec/Commons/Designators/hasTag"));
    }

    #[test]
    fn tampered_and_malformed_graphs_are_rejected() {
        let pinned = pinned_seed().unwrap();
        let mut tampered = pinned.clone();
        let V::Object(root) = &mut tampered else {
            unreachable!()
        };
        root.insert("version".into(), V::string("tampered"));
        assert_ne!(tampered, pinned);

        let mut malformed = pinned;
        let V::Object(root) = &mut malformed else {
            unreachable!()
        };
        let V::Array(claims) = root.get_mut("claims").unwrap() else {
            unreachable!()
        };
        let V::Object(first) = &mut claims[0] else {
            unreachable!()
        };
        first.insert(
            "subject".into(),
            V::string("https://example.invalid/missing"),
        );
        assert!(decode_graph(&malformed).is_err());
    }

    #[test]
    fn full_pinned_graph_lowers_to_stable_candidate_claims() {
        use cdb_core::id::{AuthorityId, GraphId, ResourceId, VersionId};
        use cdb_core::snapshot::GraphPin;

        let seed = pinned_seed().unwrap();
        let graph = decode_graph(&seed).unwrap();
        let source_hash = ContentHash::of_bytes(&seed.canonical_bytes(Limits::default()).unwrap());
        let ontology = V::object([("capture".into(), V::string("sha256:ontology"))]).unwrap();
        let capture = SnapshotRef::new(
            BackendId::new("semantic").unwrap(),
            GraphPin::new(
                AuthorityId::new("authority").unwrap(),
                GraphId::new("graph").unwrap(),
                VersionId::new("1").unwrap(),
                ResourceId::new("cid").unwrap(),
            ),
        );
        let first = build_bundles(&seed, &graph, &source_hash, &ontology, capture.clone()).unwrap();
        let second = build_bundles(&seed, &graph, &source_hash, &ontology, capture).unwrap();
        let ontology_root =
            ContentHash::of_bytes(&ontology.canonical_bytes(Limits::default()).unwrap());
        let frozen = V::object([
            ("schema".into(), V::string(CHECKPOINT_SCHEMA)),
            ("source_hash".into(), V::string(source_hash.as_str())),
            ("ontology_root".into(), V::string(ontology_root.as_str())),
            ("ontology".into(), ontology.clone()),
            (
                "backend".into(),
                V::string(first[0].validation_capture().backend().as_str()),
            ),
            ("bundles".into(), V::Array(vec![first[0].projection()])),
        ])
        .unwrap();
        let decoded = decode_frozen(&frozen, &source_hash, &ontology_root).unwrap();
        validate_frozen_batch(&seed, &graph, &source_hash, &ontology, &decoded[0], 0).unwrap();
        assert!(
            validate_frozen_batch(&seed, &graph, &source_hash, &ontology, &decoded[0], 1).is_err(),
            "a valid checkpoint for another batch must not substitute for this batch"
        );
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
            496
        );
        assert!(first
            .iter()
            .flat_map(|bundle| bundle.claims())
            .any(|claim| {
                claim.subject().as_str().contains("identifier/")
                    && claim.subject_type().as_str()
                        == "https://www.omg.org/spec/Commons/Organizations/OrganizationIdentifier"
            }));
    }

    #[test]
    fn lowering_preserves_exact_evidence_and_uses_safe_type_for_untyped_trust() {
        let seed = pinned_seed().unwrap();
        let graph = decode_graph(&seed).unwrap();
        let trust = seed
            .field("entities")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .find(|entity| entity.field("kind").unwrap().as_str().unwrap() == "trust")
            .unwrap()
            .field("id")
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(graph.entity_types[trust], OWL_THING);
        for claim in seed.field("claims").unwrap().as_array().unwrap() {
            assert!(!claim
                .field("evidence")
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty());
        }
    }
}
