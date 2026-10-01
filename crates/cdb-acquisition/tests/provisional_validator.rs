use cdb_acquisition::candidates::{
    AdvisoryBundle, AdvisoryClaim, CandidateLimits, CandidateObject, ClaimMetadata,
    EntityCandidate, LocalId, TypedLiteral,
};
use cdb_acquisition::coordinates::{CoordinateMap, LineCoordinate, LineSelection};
use cdb_acquisition::validator::{validate_provisional_bundle, ValidationInput};
use cdb_core::evidence::Utf8Span;
use cdb_core::id::{
    AuthorityId, BackendId, ContentHash, ExtractionRunId, GraphId, Iri, ResourceId, SourceId,
    VersionId,
};
use cdb_core::snapshot::{GraphPin, SnapshotRef};
use cdb_core::{CanonicalValue as V, Limits};

const ENTITY_CLASS: &str = "urn:ctxql:poc:soft:Entity";
const BUSINESS_RELATION_TYPE: &str = "urn:ctxql:acquisition:v1:BusinessRelationshipRelationType";
const BUSINESS_CLAIM_TYPE: &str = "urn:ctxql:acquisition:v1:BusinessRelationshipClaimType";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

fn capture() -> SnapshotRef {
    SnapshotRef::new(
        BackendId::new("fluree").unwrap(),
        GraphPin::new(
            AuthorityId::new("authority").unwrap(),
            GraphId::new("semantic").unwrap(),
            VersionId::new("1").unwrap(),
            ResourceId::new("cid").unwrap(),
        ),
    )
}

fn fixture() -> (AdvisoryBundle, CoordinateMap, String) {
    let text = "Alice is a borrower.\n".to_owned();
    let locator = Iri::new("file:///agreement.txt").unwrap();
    let text_version = ContentHash::of_bytes(b"converter-bound-version");
    let map = CoordinateMap::issue(
        &text,
        "attempt",
        "window",
        locator.clone(),
        text_version.clone(),
        ContentHash::of_bytes(text.as_bytes()),
        Utf8Span::new(0, text.len()).unwrap(),
    )
    .unwrap();
    let limits = CandidateLimits::default();
    let local = |value| LocalId::new(value, limits.max_local_id_bytes).unwrap();
    let entity = local("host-entity");
    let claim = local("host-claim");
    (
        AdvisoryBundle {
            local_bundle_id: local("host-bundle"),
            entities: vec![EntityCandidate::new(
                entity.clone(),
                format!(
                    "urn:ctxql:poc:soft:entity:{}",
                    &ContentHash::of_bytes(b"source\0file:///agreement.txt\0alice").as_str()[7..]
                ),
                Iri::new(ENTITY_CLASS).unwrap(),
                &limits,
            )
            .unwrap()],
            claims: vec![AdvisoryClaim {
                local_claim_id: claim.clone(),
                subject: entity,
                predicate: Iri::new(format!(
                    "urn:ctxql:poc:soft:predicate:{}",
                    &ContentHash::of_bytes(b"is a").as_str()[7..]
                ))
                .unwrap(),
                object: CandidateObject::Literal(
                    TypedLiteral::new("borrower", Iri::new(XSD_STRING).unwrap(), None, &limits)
                        .unwrap(),
                ),
                relation_type: Iri::new(BUSINESS_RELATION_TYPE).unwrap(),
                claim_type: Iri::new(BUSINESS_CLAIM_TYPE).unwrap(),
                endpoint_type_claims: vec![],
                confidence: Some("0.9".into()),
                valid_time: None,
            }],
            metadata: vec![ClaimMetadata {
                local_claim_id: claim,
                locator,
                text_version,
                coordinates: vec![LineCoordinate {
                    line_id: map.lines()[0].id.clone(),
                    selection: LineSelection::Range { start: 0, end: 19 },
                }],
                temporal_qualifier_claim: None,
            }],
        },
        map,
        text,
    )
}

fn validate(
    advisory: AdvisoryBundle,
    map: &CoordinateMap,
    text: &str,
) -> cdb_core::Result<cdb_core::semantic_admission::ValidatedSemanticBundle> {
    validate_with_descriptor(
        advisory,
        map,
        text,
        V::object([
            ("window".into(), V::string("window")),
            (
                "raw_fact".into(),
                raw_fact("Alice", "is a", "borrower", map.lines()[0].id.as_str()),
            ),
        ])
        .unwrap(),
    )
}

fn validate_with_descriptor(
    advisory: AdvisoryBundle,
    map: &CoordinateMap,
    text: &str,
    descriptor: V,
) -> cdb_core::Result<cdb_core::semantic_admission::ValidatedSemanticBundle> {
    validate_provisional_bundle(
        advisory,
        ValidationInput {
            extraction_run: ExtractionRunId::new("run").unwrap(),
            validation_capture: capture(),
            descriptor,
            source_id: SourceId::new("source").unwrap(),
            document: text,
            attempt_id: "attempt",
            window_id: "window",
            coordinates: map,
            max_spans_per_claim: 4,
            limits: Limits::default(),
        },
    )
}

fn raw_fact(subject: &str, predicate: &str, object: &str, line_id: &str) -> V {
    V::object([
        ("subject".into(), V::string(subject)),
        ("predicate".into(), V::string(predicate)),
        ("object".into(), V::string(object)),
        ("line_id".into(), V::string(line_id)),
    ])
    .unwrap()
}

#[test]
fn valid_provisional_is_grounded_capture_bound_and_deterministic() {
    let (advisory, map, text) = fixture();
    let first = validate(advisory.clone(), &map, &text).unwrap();
    let second = validate(advisory, &map, &text).unwrap();
    assert_eq!(first.projection(), second.projection());
    assert_eq!(first.claims().len(), 1);
    assert_eq!(
        first.claims()[0]
            .ext()
            .field("ctxql.acquisition/v1")
            .unwrap()
            .field("mapping_status")
            .unwrap()
            .as_str()
            .unwrap(),
        "provisional"
    );
    assert_eq!(first.validation_capture(), &capture());
    assert_eq!(
        first.claims()[0].lineage().sources()[0]
            .verify(text.as_bytes())
            .unwrap(),
        cdb_core::evidence::VerificationOutcome::Verified
    );
}

#[test]
fn raw_fact_labels_are_queryable_but_must_match_host_claim() {
    let (mut advisory, map, text) = fixture();
    let subject = "Alice";
    let relation = "is a";
    let iri = |prefix: &str, label: &str| {
        format!(
            "{prefix}{}",
            &ContentHash::of_bytes(label.to_lowercase().as_bytes()).as_str()[7..]
        )
    };
    advisory.entities[0] = EntityCandidate::new(
        advisory.entities[0].local_id().clone(),
        iri(
            "urn:ctxql:poc:soft:entity:",
            &format!("source\0file:///agreement.txt\0{subject}"),
        ),
        Iri::new(ENTITY_CLASS).unwrap(),
        &CandidateLimits::default(),
    )
    .unwrap();
    advisory.claims[0].predicate =
        Iri::new(iri("urn:ctxql:poc:soft:predicate:", relation)).unwrap();
    let descriptor = |predicate: &str| {
        V::object([(
            "raw_fact".into(),
            V::object([
                ("subject".into(), V::string(subject)),
                ("predicate".into(), V::string(predicate)),
                ("object".into(), V::string("borrower")),
                ("line_id".into(), V::string(map.lines()[0].id.as_str())),
            ])
            .unwrap(),
        )])
        .unwrap()
    };
    let validated =
        validate_with_descriptor(advisory.clone(), &map, &text, descriptor(relation)).unwrap();
    let ext = validated.claims()[0]
        .ext()
        .field("ctxql.acquisition/v1")
        .unwrap();
    assert_eq!(
        ext.field("subject_label").unwrap().as_str().unwrap(),
        subject
    );
    assert_eq!(
        ext.field("predicate_label").unwrap().as_str().unwrap(),
        relation
    );
    assert!(
        validate_with_descriptor(advisory.clone(), &map, &text, descriptor("invented")).is_err()
    );
    assert!(validate_with_descriptor(
        advisory.clone(),
        &map,
        &text,
        V::object([(
            "raw_fact".into(),
            raw_fact(subject, relation, "borrower", "other-line")
        )])
        .unwrap(),
    )
    .is_err());
    assert!(validate_with_descriptor(
        advisory,
        &map,
        &text,
        V::object([("window".into(), V::string("window"))]).unwrap(),
    )
    .is_err());
}

#[test]
fn rejects_external_iris_and_unsafe_metadata() {
    let (advisory, map, text) = fixture();

    let mut external_predicate = advisory.clone();
    external_predicate.claims[0].predicate = Iri::new("https://example.test/model-term").unwrap();
    assert!(validate(external_predicate, &map, &text).is_err());

    let mut external_subject = advisory.clone();
    external_subject.entities[0] = EntityCandidate::new(
        external_subject.entities[0].local_id().clone(),
        "https://example.test/model-entity",
        Iri::new(ENTITY_CLASS).unwrap(),
        &CandidateLimits::default(),
    )
    .unwrap();
    assert!(validate(external_subject, &map, &text).is_err());

    let mut endpoint_assertion = advisory.clone();
    let claim_id = endpoint_assertion.claims[0].local_claim_id.clone();
    endpoint_assertion.claims[0]
        .endpoint_type_claims
        .push(claim_id);
    assert!(validate(endpoint_assertion, &map, &text).is_err());

    let mut ungrounded_time = advisory;
    ungrounded_time.claims[0].valid_time = Some("2026-09-22T00:00:00.000Z".into());
    assert!(validate(ungrounded_time, &map, &text).is_err());
}
