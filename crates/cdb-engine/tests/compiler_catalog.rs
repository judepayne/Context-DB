use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    id::{ContentHash, Iri, VersionId},
    ErrorKind, Limits, Timestamp,
};
use cdb_engine::{
    artifacts::{ArtifactKind, ArtifactName, Catalog, CatalogOptions},
    compiler::{compile, QuerySource, SelectedProfile},
    options::CompileOptions,
};

fn artifact(name: &str, bytes: &[u8]) -> PublishedArtifact {
    PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new(format!("ctxql:{name}")).unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(bytes),
        ),
        bytes.to_vec(),
        Limits::default(),
    )
    .unwrap()
}
fn config() -> PublishedArtifact {
    artifact("config/test", br#"{"name":"test","version":"1","runtime":{"candidate_order":["depth asc","confidence desc","transaction_time desc","claim_id asc"],"path_ranking":["shorter_path","higher_accumulated_confidence","better_grounding","newer_claims","claim_id_tiebreak"],"cycle_policy":"no_repeated_claim"},"fields":{},"external_functions":{}}"#)
}
#[test]
fn catalog_profile_compiles_without_changing_its_published_identity() {
    let profile = artifact(
        "profile/risk",
        br#"{ "name": "risk", "bounds": {"max_depth": 1} }"#,
    );
    let catalog = Catalog::new(
        [(
            ArtifactKind::Profile,
            ArtifactName::new("risk", 100).unwrap(),
            profile.clone(),
        )],
        CatalogOptions {
            limits: Limits::default(),
            max_entries: 1,
            max_name_bytes: 100,
            max_retained_bytes: 4096,
        },
    )
    .unwrap();
    let selected = catalog
        .resolve(
            ArtifactKind::Profile,
            &ArtifactName::new("risk", 100).unwrap(),
            profile.reference(),
        )
        .unwrap();
    let config = config();
    let plan = compile(
        QuerySource::inline(br#"{"profile":"risk","about":[{"from":["s"],"match":"exact"}]}"#),
        Some(SelectedProfile {
            selector: "risk",
            artifact: selected,
        }),
        &config,
        CompileOptions::default(),
    )
    .unwrap()
    .finalize(Timestamp::from_millis(0).unwrap())
    .unwrap();
    assert_eq!(
        plan.projection()
            .canonical()
            .payload()
            .field("artifacts")
            .unwrap()
            .field("profile")
            .unwrap(),
        &profile.reference().projection()
    );
}
#[test]
fn authored_profile_selector_is_a_safe_name_not_a_new_reference_object_syntax() {
    let profile = artifact("profile/risk", br#"{"bounds":{"max_depth":1}}"#);
    let config = config();
    for selector in ["../risk", "/risk", "bank\\risk"] {
        let escaped = selector.replace('\\', "\\\\");
        let query =
            format!(r#"{{"profile":"{escaped}","about":[{{"from":["s"],"match":"exact"}}]}}"#);
        let result = compile(
            QuerySource::inline(query.as_bytes()),
            Some(SelectedProfile {
                selector,
                artifact: &profile,
            }),
            &config,
            CompileOptions::default(),
        );
        assert!(
            matches!(result,Err(e) if e.kind==ErrorKind::Invalid),
            "{selector}"
        );
    }
    let reference = String::from_utf8(
        profile
            .reference()
            .projection()
            .canonical_bytes(Limits::default())
            .unwrap(),
    )
    .unwrap();
    let query = format!(r#"{{"profile":{reference},"about":[{{"from":["s"],"match":"exact"}}]}}"#);
    assert!(compile(
        QuerySource::inline(query.as_bytes()),
        Some(SelectedProfile {
            selector: "risk",
            artifact: &profile
        }),
        &config,
        CompileOptions::default()
    )
    .is_err());
}
