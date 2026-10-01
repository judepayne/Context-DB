use cdb_backend_fluree::{AuthorityOptions, FlureeBackend};
use cdb_core::{admission::*, claim::*, id::*, snapshot::*, CanonicalValue as V, Limits};
use cdb_projection_redb::{GenerationOptions, RedbProjection};
use cdb_testkit::{assertions::assert_backend_projection, reference_fixture::FixtureBuilder};

#[tokio::test]
async fn native_backend_projection_raw_contract_with_held_pins() {
    let root = tempfile::tempdir().unwrap();
    let backend = FlureeBackend::create(AuthorityOptions::new(
        root.path().join("authority"),
        "p3-contracts:main".into(),
        BackendId::new("p3-contracts").unwrap(),
        AuthorityId::new("contracts").unwrap(),
        GraphId::new("graph").unwrap(),
    ))
    .await
    .unwrap();
    let generation = VersionId::new("live").unwrap();
    let algorithm = Iri::new("urn:p3:raw").unwrap();
    let binding = ProjectionCheckpoint::new(
        backend.head().await.unwrap(),
        VersionId::new("ctxql-projection/v1").unwrap(),
        generation.clone(),
        algorithm.clone(),
    )
    .unwrap();
    let projection = RedbProjection::create(
        root.path().join("projection"),
        binding,
        GenerationOptions::default(),
    )
    .await
    .unwrap();
    let mut builder = FixtureBuilder::new();
    builder
        .entity("urn:a", Some("A"))
        .unwrap()
        .entity("urn:b", Some("B"))
        .unwrap();
    for id in ["urn:c1", "urn:c2"] {
        builder
            .edge(
                id,
                "urn:a",
                ClaimObject::Entity(EntityId::new("urn:b").unwrap()),
                "0.8",
            )
            .unwrap();
    }
    builder
        .edge(
            "urn:loop",
            "urn:a",
            ClaimObject::Entity(EntityId::new("urn:a").unwrap()),
            "0.8",
        )
        .unwrap();
    let first = builder.into_batch().unwrap();
    let mut later = first.claims()[0].projection().as_object().unwrap().clone();
    later.insert("claim_id".into(), V::string("urn:future-claim"));
    later.insert("subject_id".into(), V::string("urn:future"));
    let mut lifecycle = Vec::new();
    for (id, relation, reference) in [
        ("urn:supersede", "ctxql:superseded_by", "urn:c2"),
        ("urn:contradict", "ctxql:contradicted_by", "urn:c2"),
        ("urn:retract", "ctxql:retracted_by", "urn:event"),
    ] {
        let mut fields = first.claims()[0].projection().as_object().unwrap().clone();
        fields.insert("claim_id".into(), V::string(id));
        fields.insert("subject_id".into(), V::string("urn:c1"));
        fields.insert("relation".into(), V::string(relation));
        fields.insert("object_id".into(), V::string(reference));
        fields.insert(
            "ext".into(),
            V::Object([("reason".into(), V::string("full lifecycle content"))].into()),
        );
        lifecycle.push(LifecycleAssertion::from_value(&V::Object(fields)).unwrap());
    }
    let ResourceChange::Add(original) = &first.resources()[0] else {
        panic!("fixture add")
    };
    let future = DependencyRecord::new(
        "ctxql-resource/v1",
        ResourceId::new("urn:future").unwrap(),
        original.kind(),
        original.facts().to_vec(),
    )
    .unwrap();
    let second = AdmissionBatch::new(
        vec![CandidateClaim::from_value(&V::Object(later)).unwrap()],
        lifecycle,
        vec![
            ResourceChange::Add(future),
            ResourceChange::Add(
                DependencyRecord::new(
                    "ctxql-resource/v1",
                    ResourceId::new("urn:event").unwrap(),
                    ResourceKind::LifecycleEvent,
                    original.facts().to_vec(),
                )
                .unwrap(),
            ),
        ],
        vec![],
        V::Object(Default::default()),
        Limits::default(),
    )
    .unwrap();
    assert_backend_projection(
        &backend,
        &projection,
        &[
            (IdempotencyKey::new("first").unwrap(), first),
            (IdempotencyKey::new("second").unwrap(), second),
        ],
        generation,
        algorithm,
        1000,
    )
    .await
    .unwrap();
}
