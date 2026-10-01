use cdb_backend_fluree::semantic_codec::SemanticCodecLimits;
use cdb_backend_fluree::{
    semantic_policy::resolve_current_semantic_authority, FlureeSemanticLedger,
    FlureeSemanticWriter, SemanticLedgerOptions, SemanticWriterOptions,
};
use cdb_core::acquisition::{
    AdmissionRecovery, BundlePrepared, ReviewAdmissionRecovery, SemanticBundleWriter,
};
use cdb_core::claim::CandidateClaim;
use cdb_core::id::{
    AttemptId, AuthorityId, BackendId, BundleId, ContentHash, ExtractionRunId, GraphId, Iri, JobId,
};
use cdb_core::review::{
    ReviewAssertionIntent, ReviewBundlePrepared, ReviewRecord, ReviewRecordId,
    ValidatedReviewBundle, VocabularyVerdict,
};
use cdb_core::semantic_admission::{stable_acquisition_v2_claim_id, ValidatedSemanticBundle};
use cdb_core::{snapshot::PageSize, CanonicalValue as V, Limits, Timestamp};
use fluree_db_api::FlureeBuilder;
use std::process::Command;

const GRAPH: &str = "urn:ctxql:p6:claims";

fn v2_integer_candidate(id: &str, subject: &str) -> CandidateClaim {
    let json = format!(
        r#"{{"claim_id":"{id}","claim_type":"urn:type:claim","confidence":1,"ext":{{"ctxql.acquisition.v2/claim_identity":"stable-component/v1","ctxql.acquisition.v2/component_ref":"window:1#attribute:a1"}},"grounding_level":"claim_only","lineage":{{"schema":"ctxql.lineage.v1","sources":[]}},"object_id":{{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#integer","value":42,"language":null}},"object_type":"http://www.w3.org/2001/XMLSchema#integer","relation":"urn:relation:count","relation_type":"urn:type:relation","subject_id":"{subject}","subject_type":"urn:type:entity"}}"#
    );
    CandidateClaim::from_value(&V::parse(json.as_bytes(), Limits::default()).unwrap()).unwrap()
}

fn options() -> SemanticLedgerOptions {
    SemanticLedgerOptions {
        backend: BackendId::new("fluree:p6-writer").unwrap(),
        authority: AuthorityId::new("fluree:p6-writer-authority").unwrap(),
        ledger: GraphId::new("p6-writer:main").unwrap(),
    }
}

#[tokio::test]
async fn process_lease_and_atomic_recover_or_admit_are_enforced() {
    if let Ok(path) = std::env::var("CTXQL_P6_WRITER_CHILD") {
        let reader = FlureeSemanticLedger::open_file(&path, options())
            .await
            .unwrap();
        let authority = resolve_current_semantic_authority(
            &reader,
            "urn:ctxql:trusted-acquisition",
            "https://ns.flur.ee/db#modify",
        )
        .await
        .unwrap();
        let attempted = FlureeSemanticWriter::open_file(
            &path,
            SemanticWriterOptions {
                reader: options(),
                claims_graph: Iri::new(GRAPH).unwrap(),
                review_graph: Iri::new("urn:ctxql:review").unwrap(),
                codec_limits: SemanticCodecLimits::default(),
                review_codec_limits: Default::default(),
                extraction_limits: Default::default(),
                authority: authority.basis,
            },
        )
        .await;
        assert!(
            attempted.is_err(),
            "competing process acquired writer lease"
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let fluree = FlureeBuilder::file(directory.path().to_string_lossy().into_owned())
        .without_indexing()
        .build()
        .unwrap();
    let ledger = fluree.create_ledger("p6-writer:main").await.unwrap();
    let config_graph = "urn:fluree:p6-writer:main#config";
    let ledger = fluree
        .stage_owned(ledger)
        .upsert_turtle(&format!(
            r#"
            @prefix f: <https://ns.flur.ee/db#> .
            @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
            @prefix owl: <http://www.w3.org/2002/07/owl#> .
            @prefix ctxql: <https://ctxql.example/semantic-rdf/v1/> .
            GRAPH <{config_graph}> {{
              <urn:config> rdf:type f:LedgerConfig ;
                f:reasoningDefaults <urn:reasoning> ;
                ctxql:governedDataGraph <{GRAPH}> ;
                ctxql:claimGraph <{GRAPH}> ;
                ctxql:infrastructureGraph <urn:p6:schema> .
              <urn:reasoning> f:reasoningModes f:owl2rl ;
                f:schemaSource <urn:schema-ref> ; f:followOwlImports false .
              <urn:schema-ref> rdf:type f:GraphRef ; f:graphSource <urn:schema-source> .
              <urn:schema-source> f:graphSelector <urn:p6:schema> .
            }}
            GRAPH <urn:p6:schema> {{ <urn:p6:schema> rdf:type owl:Ontology . }}
            "#
        ))
        .execute()
        .await
        .unwrap()
        .ledger;
    drop(ledger);
    drop(fluree);

    let reader = FlureeSemanticLedger::open_file(directory.path(), options())
        .await
        .unwrap();
    let capture = cdb_core::contracts::SemanticProjectionSource::head(&reader)
        .await
        .unwrap();
    let authority = resolve_current_semantic_authority(
        &reader,
        "urn:ctxql:trusted-acquisition",
        "https://ns.flur.ee/db#modify",
    )
    .await
    .unwrap();
    let writer_options = SemanticWriterOptions {
        reader: options(),
        claims_graph: Iri::new(GRAPH).unwrap(),
        review_graph: Iri::new("urn:ctxql:review").unwrap(),
        codec_limits: SemanticCodecLimits::default(),
        review_codec_limits: Default::default(),
        extraction_limits: Default::default(),
        authority: authority.basis,
    };
    let writer = FlureeSemanticWriter::open_file(directory.path(), writer_options.clone())
        .await
        .unwrap();
    let restart_options = writer_options.clone();
    assert!(
        FlureeSemanticWriter::open_file(directory.path(), writer_options)
            .await
            .is_err()
    );
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "process_lease_and_atomic_recover_or_admit_are_enforced",
            "--nocapture",
        ])
        .env("CTXQL_P6_WRITER_CHILD", directory.path())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "competing writer process failed unexpectedly: {}",
        String::from_utf8_lossy(&child.stderr)
    );

    let bundle_id = BundleId::new("bundle:writer").unwrap();
    let extraction_run = ExtractionRunId::new("run:writer").unwrap();
    let descriptor = V::object([
        (
            "schema".into(),
            V::string("ctxql-extraction-admission-descriptor/v2"),
        ),
        ("evaluation_id".into(), V::string("evaluation:writer")),
    ])
    .unwrap();
    let provisional = v2_integer_candidate("urn:ctxql:provisional:writer", "urn:entity:a");
    let claim_id = stable_acquisition_v2_claim_id(&provisional, Limits::default()).unwrap();
    let claim = v2_integer_candidate(claim_id.as_str(), "urn:entity:a");
    let bundle = ValidatedSemanticBundle::new(
        bundle_id,
        extraction_run,
        capture,
        descriptor,
        vec![("local-writer".into(), claim)],
        Limits::default(),
    )
    .unwrap();
    let prepared = BundlePrepared {
        job_id: JobId::new("job:writer").unwrap(),
        attempt_id: AttemptId::new("attempt:writer").unwrap(),
        bundle_id: bundle.id().clone(),
        admission_key: bundle.admission_key().as_str().to_owned(),
        descriptor_root: bundle.descriptor_root().clone(),
        payload_root: bundle.payload_root().clone(),
        canonical_claim_root: bundle.canonical_claim_root().clone(),
        expected_claim_ids: bundle.expected_claim_ids(),
        validation_capture: bundle.validation_capture().clone(),
        source_selector_root: ContentHash::of_bytes(b"selectors"),
        safe_counts: V::object([("claims".into(), V::integer(1))]).unwrap(),
        recorded_at: Timestamp::parse("2026-09-22T00:00:00.000Z").unwrap(),
    };
    let receipt = writer.recover_or_admit(&prepared, &bundle).await.unwrap();
    assert_eq!(receipt.claim_ids(), bundle.expected_claim_ids());
    let refreshed = cdb_core::contracts::SemanticProjectionSource::head(&reader)
        .await
        .unwrap();
    assert_eq!(&refreshed, receipt.snapshot());
    let snapshot =
        cdb_core::contracts::SemanticProjectionSource::open_snapshot(&reader, receipt.snapshot())
            .await
            .unwrap();
    let exported = snapshot
        .export(None, PageSize::new(16).unwrap())
        .await
        .unwrap();
    assert_eq!(exported.items().len(), 1);
    assert!(
        writer.preflight(&bundle).await.is_err(),
        "a committed head must make the prior validation capture stale"
    );
    assert!(matches!(
        writer.recover(&prepared).await.unwrap(),
        AdmissionRecovery::Exact(_)
    ));
    let mut wrong_business_attempt = prepared.clone();
    wrong_business_attempt.attempt_id = AttemptId::new("attempt:writer:wrong").unwrap();
    assert_eq!(
        writer.recover(&wrong_business_attempt).await.unwrap(),
        AdmissionRecovery::Conflict,
        "matching marker data from a different attempt must not recover"
    );
    let mut unrelated_business_attempt = prepared.clone();
    unrelated_business_attempt.attempt_id = AttemptId::new("attempt:writer:unrelated").unwrap();
    unrelated_business_attempt.admission_key = "p6:unrelated-admission".into();
    unrelated_business_attempt.descriptor_root = ContentHash::of_bytes(b"unrelated descriptor");
    unrelated_business_attempt.payload_root = ContentHash::of_bytes(b"unrelated payload");
    assert_eq!(
        writer.recover(&unrelated_business_attempt).await.unwrap(),
        AdmissionRecovery::Conflict,
        "matching v2 claims committed for an unrelated attempt must not recover"
    );

    let review_record = ReviewRecord::new(
        ReviewRecordId::new("urn:ctxql:review:writer").unwrap(),
        "window:1#0",
        "urn:ctxql:source:writer",
        ContentHash::of_bytes(b"review-artifact"),
        VocabularyVerdict::Rejected,
        ReviewAssertionIntent::None,
        vec!["ambiguous_property".into()],
        vec!["model:hasParty".into()],
        vec!["model:Borrower".into()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let review_bundle = ValidatedReviewBundle::new(
        BundleId::new("bundle:review-writer").unwrap(),
        "evaluation:writer",
        "job:writer",
        AttemptId::new("attempt:writer").unwrap(),
        refreshed.clone(),
        vec![review_record],
        Limits::default(),
    )
    .unwrap();
    let review_prepared = ReviewBundlePrepared::new(
        JobId::new("job:writer").unwrap(),
        &review_bundle,
        Timestamp::parse("2026-09-22T00:02:00.000Z").unwrap(),
    );
    assert_eq!(
        writer.recover_review(&review_prepared).await.unwrap(),
        ReviewAdmissionRecovery::Absent
    );
    let review_receipt = writer
        .recover_or_admit_review(&review_prepared, &review_bundle)
        .await
        .unwrap();
    assert_eq!(
        review_receipt.review_ids(),
        review_bundle.expected_review_ids()
    );
    // Simulate a lost acknowledgement: exact Semantic history is sufficient
    // before a Control receipt exists, and retry never duplicates the write.
    assert_eq!(
        writer.recover_review(&review_prepared).await.unwrap(),
        ReviewAdmissionRecovery::Exact(Box::new(review_receipt.clone()))
    );
    let mut wrong_payload = review_prepared.clone();
    wrong_payload.payload_root = ContentHash::of_bytes(b"different exact review payload");
    assert_eq!(
        writer.recover_review(&wrong_payload).await.unwrap(),
        ReviewAdmissionRecovery::Conflict,
        "attempt marker alone must not recover a different payload"
    );
    assert_eq!(
        writer
            .recover_or_admit_review(&review_prepared, &review_bundle)
            .await
            .unwrap(),
        review_receipt
    );
    assert!(writer.preflight(&bundle).await.is_err());
    drop(writer);
    let restarted = FlureeSemanticWriter::open_file(directory.path(), restart_options)
        .await
        .unwrap();
    assert!(matches!(
        restarted.recover(&prepared).await.unwrap(),
        AdmissionRecovery::Exact(_)
    ));
    assert_eq!(
        restarted.recover_review(&review_prepared).await.unwrap(),
        ReviewAdmissionRecovery::Exact(Box::new(review_receipt))
    );
}
