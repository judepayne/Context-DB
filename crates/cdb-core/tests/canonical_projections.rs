mod common;
use cdb_core::{
    artifact::*, claim::*, id::*, projection::*, CanonicalValue as V, Limits, Timestamp,
};
use common::*;
#[test]
fn typed_response_omits_unselected_and_transport_diagnostics() {
    let claim = ResponseClaim::new(
        AdmittedClaim::assign(candidate("a"), Timestamp::from_millis(0).unwrap()),
        LifecycleState::Contradicted,
    );
    let p = ResponseProjection::new(
        ReturnSelection::default(),
        GraphStatus::Ready,
        vec!["z".into(), "a".into(), "z".into()],
        vec![],
        vec![claim],
        vec![],
        None,
    )
    .unwrap();
    assert!(p.canonical().hash(Limits::default()).is_ok());
    assert_eq!(p.canonical().payload().field("explain").unwrap(), &V::Null);
    let selection = ReturnSelection {
        claims: false,
        paths: false,
        evidence: false,
        explain: false,
    };
    let p = ResponseProjection::new(
        selection,
        GraphStatus::Ready,
        vec![],
        vec![],
        vec![],
        vec![],
        None,
    )
    .unwrap();
    assert_eq!(p.canonical().payload().field("claims").unwrap(), &V::Null);
}
#[test]
fn function_domains_indices_and_empty_roots() {
    let m = FunctionManifest::new(
        ResourceId::new("f").unwrap(),
        VersionId::new("1").unwrap(),
        json("{}"),
        Limits::default(),
    )
    .unwrap();
    let input = FunctionCallProjection::new(false, &m, 0, json("0.1")).unwrap();
    let output = FunctionCallProjection::new(true, &m, 0, json("0.1")).unwrap();
    let next = FunctionCallProjection::new(false, &m, 1, json("0.1")).unwrap();
    let h = |p: &cdb_core::canonical::CanonicalProjection| p.hash(Limits::default()).unwrap();
    assert_ne!(h(input.canonical()), h(output.canonical()));
    assert_ne!(h(input.canonical()), h(next.canonical()));
    assert_ne!(
        h(FunctionRootProjection::new(false, &m, &[])
            .unwrap()
            .canonical()),
        h(FunctionRootProjection::new(true, &m, &[])
            .unwrap()
            .canonical())
    );
}
#[test]
fn path_endpoint_shape_and_literal_identity() {
    let p = json(
        r#"{"seed_id":"s","node_ids":["s"],"endpoints":[{"kind":"iri","value":"s"},{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#string","value":"urn:looks-like-entity","language":null}],"claim_ids":["c"],"depth":1,"reached_target":null,"block_index":0,"scores":{"accumulated_confidence":0.5,"grounding_level":"claim_only"}}"#,
    );
    assert!(PathProjection::from_value(&p).is_ok());
    let mut bad = p;
    set(&mut bad, "depth", V::integer(2));
    assert!(PathProjection::from_value(&bad).is_err());
}
#[test]
fn path_seed_literals_and_target_use_actual_endpoint_positions() {
    let seed = json(r#"{"kind":"iri","value":"s"}"#);
    let target = json(r#"{"kind":"iri","value":"t"}"#);
    let literal = json(
        r#"{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#string","value":"s","language":null}"#,
    );
    let base = json(
        r#"{"seed_id":"s","node_ids":["s"],"endpoints":[],"claim_ids":["c"],"depth":1,"reached_target":null,"block_index":0,"scores":{"accumulated_confidence":0.5,"grounding_level":"claim_only"}}"#,
    );
    for (endpoints, nodes, reached, valid) in [
        (
            vec![literal.clone(), seed.clone()],
            json(r#"["s"]"#),
            V::Null,
            false,
        ),
        (
            vec![seed.clone(), literal.clone()],
            json(r#"["s"]"#),
            V::string("s"),
            false,
        ),
        (
            vec![seed.clone(), literal.clone(), target.clone()],
            json(r#"["s","t"]"#),
            V::string("t"),
            false,
        ),
        (vec![seed.clone(), literal], json(r#"["s"]"#), V::Null, true),
        (
            vec![seed, target],
            json(r#"["s","t"]"#),
            V::string("t"),
            true,
        ),
    ] {
        let mut path = base.clone();
        let depth = endpoints.len() - 1;
        set(&mut path, "depth", V::integer(depth as u64));
        set(
            &mut path,
            "claim_ids",
            V::Array((0..depth).map(|i| V::string(format!("c{i}"))).collect()),
        );
        set(&mut path, "endpoints", V::Array(endpoints));
        set(&mut path, "node_ids", nodes);
        set(&mut path, "reached_target", reached);
        assert_eq!(PathProjection::from_value(&path).is_ok(), valid, "{path:?}");
    }
}
#[test]
fn text_normalization_only_products() {
    assert_eq!(normalize_product_text(""), "\n");
    assert_eq!(normalize_product_text("x\r\ny\r"), "x\ny\n");
    assert_eq!(normalize_product_text("x"), normalize_product_text("x\n"));
    assert_ne!(normalize_product_text("x"), normalize_product_text("x\n\n"));
}
#[test]
fn semantic_config_rejects_obsolete_native_authority_selector() {
    let mut config = fixture("plan")
        .field("payload")
        .unwrap()
        .field("config")
        .unwrap()
        .clone();
    let V::Object(fields) = &mut config else {
        panic!("config fixture must be an object");
    };
    fields.insert(
        "native_interpretation".into(),
        json(r#"{"mode":"obsolete","resources":[],"claims":[],"mappings":{}}"#),
    );
    let error = SemanticConfig::from_value(&config).unwrap_err();
    assert_eq!(error.message, "unknown field native_interpretation");
}

#[test]
fn typed_plan_excludes_assembly_and_operational_options() {
    let payload = fixture("plan").field("payload").unwrap().clone();
    let q = NormalizedQuery::from_value(payload.field("query").unwrap()).unwrap();
    let config = SemanticConfig::from_value(payload.field("config").unwrap()).unwrap();
    let reference =
        ArtifactRef::from_value(payload.field("artifacts").unwrap().field("config").unwrap())
            .unwrap();
    let p = PlanProjection::new(
        q,
        None,
        None,
        reference,
        config,
        Timestamp::parse(payload.field("as_of").unwrap().as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(p.canonical().payload(), &payload);
    assert!(p.canonical().payload().field("assembly").is_err());
}
