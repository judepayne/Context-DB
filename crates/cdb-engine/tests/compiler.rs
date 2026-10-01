use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    id::{ContentHash, Iri, VersionId},
    CanonicalValue as V, ErrorKind, Limits, Timestamp,
};
use cdb_engine::{compiler::*, options::CompileOptions, values::Value};
const CONFIG: &str = r#"{"name":"fixture","version":"1","runtime":{"candidate_order":["depth asc","confidence desc","transaction_time desc","claim_id asc"],"path_ranking":["shorter_path","higher_accumulated_confidence","better_grounding","newer_claims","claim_id_tiebreak"],"cycle_policy":"no_repeated_claim"},"fields":{},"external_functions":{}}"#;
fn artifact(name: &str, bytes: &str) -> PublishedArtifact {
    PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new(format!("urn:{name}")).unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(bytes.as_bytes()),
        ),
        bytes.as_bytes().to_vec(),
        Limits::default(),
    )
    .unwrap()
}
fn cutoff() -> Timestamp {
    Timestamp::parse("2026-03-31T00:00:00Z").unwrap()
}
fn compile_q(q: &str) -> cdb_core::Result<ValidatedDraft> {
    compile(
        QuerySource::inline(q.as_bytes()),
        None,
        &artifact("config", CONFIG),
        CompileOptions::default(),
    )
}
fn query(extra: &str) -> String {
    format!(r#"{{"about":[{{"from":["A"],"match":"exact"}}],"bounds":{{"max_depth":2}}{extra}}}"#)
}
#[test]
fn defaults_cutoff_and_projection() {
    let draft = compile_q(&query("")).unwrap();
    assert_eq!(draft.requested_as_of(), None);
    let plan = draft.finalize(cutoff()).unwrap();
    assert_eq!(
        plan.caps(),
        Caps {
            max_depth: 2,
            seed_limit: 2,
            fanout_limit: 4,
            max_claims: 16,
            path_limit: 8
        }
    );
    assert_eq!(plan.direction(), Direction::Outgoing);
    assert_eq!(plan.blocks()[0].from(), ["A"]);
    assert_eq!(plan.blocks()[0].to(), None);
    let payload = plan.projection().canonical().payload();
    assert_eq!(
        payload
            .field("query")
            .unwrap()
            .field("bounds")
            .unwrap()
            .field("as_of")
            .unwrap(),
        payload.field("as_of").unwrap()
    );
    assert_eq!(
        plan.hash(),
        &plan
            .projection()
            .canonical()
            .hash(Limits::default())
            .unwrap()
    );
    assert_eq!(
        payload.field("artifacts").unwrap().field("query").unwrap(),
        &V::Null
    );
    assert!(!payload
        .field("query")
        .unwrap()
        .as_object()
        .unwrap()
        .contains_key("@context"));
}
#[test]
fn parser_negative_matrix() {
    for (id, q) in [
        ("duplicates", r#"{"about":[],"about":[]}"#),
        ("decoded-duplicates", r#"{"bounds":{},"\u0062ounds":{}}"#),
        ("comments", "{/*bad*/}"),
        ("nonfinite", "{\"x\":NaN}"),
        ("unknown", r#"{"wat":2}"#),
        ("null", r#"{"bounds":null}"#),
    ] {
        assert!(compile_q(q).is_err(), "{id}");
    }
    assert!(compile(
        QuerySource::inline(&[255]),
        None,
        &artifact("c", CONFIG),
        CompileOptions::default()
    )
    .is_err());
}
#[test]
fn caps_zero_missing_negative_overflow_and_null() {
    for (id, bounds) in [
        ("missing", "{}"),
        ("negative", r#"{"max_depth":-1}"#),
        ("fraction", r#"{"max_depth":1.5}"#),
        ("overflow", r#"{"max_depth":18446744073709551616}"#),
        ("null", r#"{"max_depth":null}"#),
    ] {
        let q = format!(r#"{{"about":[{{"from":["A"],"match":"exact"}}],"bounds":{bounds}}}"#);
        assert!(compile_q(&q).is_err(), "{id}");
    }
    let p = compile_q(r#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":0,"path_limit":0,"seed_limit":0,"fanout_limit":0,"max_claims":0}}"#).unwrap().finalize(cutoff()).unwrap();
    assert_eq!(p.caps().path_limit, 0);
    assert_eq!(p.caps().max_depth, 0);
}
#[test]
fn approximate_is_not_exact_and_invalid_is_not_unsupported() {
    for q in [
        r#"{"about":[{"from":["A"]}],"bounds":{"max_depth":1}}"#,
        r#"{"about":[{"from":["A"],"match":"approximate"}],"bounds":{"max_depth":1}}"#,
    ] {
        assert_eq!(compile_q(q).unwrap_err().kind, ErrorKind::Unsupported);
    }
    for extra in [
        r#", "walk":{"predicates":[["meta:wat","=",1]]}"#,
        r#", "walk":{"predicates":[["meta:confidence","wat",1]]}"#,
        r#", "walk":{"predicates":[["meta:confidence","=","1"]]}"#,
    ] {
        assert_eq!(
            compile_q(&query(extra)).unwrap_err().kind,
            ErrorKind::Invalid
        );
    }
    for extra in [
        r#", "walk":{"predicates":[["meta:claim_type","isa","urn:T"]]}"#,
        r#", "filter":{"predicates":[{"keep":"true"}]}"#,
    ] {
        assert_eq!(
            compile_q(&query(extra)).unwrap_err().kind,
            ErrorKind::Unsupported
        );
    }
}
#[test]
fn merged_unsupported_drop_replace_clear_and_phase_local_identity() {
    let p = artifact(
        "p",
        r#"{"name":"p","about":42,"bounds":{"max_depth":3},"walk":{"predicates":[["meta:confidence",">",0],{"name":"custom","keep":"true"},{"name":"other","where":["meta:depth",">",0]}]},"filter":{"predicates":[{"name":"other","where":["meta:depth",">",0]}]}}"#,
    );
    for (overlay, names) in [
        (
            r#""walk":{"drop_predicates":["custom","unknown"],"predicates":[{"name":"other","where":["meta:depth",">",1]},{"name":"custom","where":["meta:depth","<",9]}]}"#,
            vec![None, Some("other"), Some("custom")],
        ),
        (
            r#""walk":{"predicates":[{"name":"custom","where":["meta:depth",">",1]}]}"#,
            vec![None, Some("custom"), Some("other")],
        ),
        (r#""walk":{"predicates":[]}"#, vec![]),
    ] {
        let q =
            format!(r#"{{"profile":"p","about":[{{"from":["A"],"match":"exact"}}],{overlay}}}"#);
        let draft = compile(
            QuerySource::inline(q.as_bytes()),
            Some(SelectedProfile {
                selector: "p",
                artifact: &p,
            }),
            &artifact("c", CONFIG),
            CompileOptions::default(),
        )
        .unwrap();
        assert_eq!(draft.notices()[0].code(), "ignored_profile_about");
        let plan = draft.finalize(cutoff()).unwrap();
        assert_eq!(
            plan.walk_predicates()
                .iter()
                .map(CompiledPredicate::name)
                .collect::<Vec<_>>(),
            names
        );
        for (i, p) in plan.walk_predicates().iter().enumerate() {
            assert_eq!(p.index(), i);
            assert_eq!(p.phase(), Phase::Walk);
        }
        assert_eq!(plan.filter_predicates().len(), 1);
    }
}
#[test]
fn source_duplicate_names_rejected_even_when_cleared() {
    let p = artifact(
        "p",
        r#"{"walk":{"predicates":[{"name":"a","keep":"true"},{"name":"a","keep":"false"}]}}"#,
    );
    let q = query(r#", "profile":"p","walk":{"predicates":[]}"#);
    assert_eq!(
        compile(
            QuerySource::inline(q.as_bytes()),
            Some(SelectedProfile {
                selector: "p",
                artifact: &p
            }),
            &artifact("c", CONFIG),
            CompileOptions::default()
        )
        .unwrap_err()
        .kind,
        ErrorKind::Invalid
    );
}
#[test]
fn prefix_and_bound_normalization_is_position_local() {
    let q = r#"{"@context":{"ex":"https://example.org/"},"about":[{"from":["ex:A","opaque:label"],"match":"exact"}],"bounds":{"max_depth":1,"type":"ex:T","raw":{"label":"ex:T"}},"walk":{"predicates":[["meta:claim_type","=","bound:type"],["meta:ext:label","=","ex:T"]]}}"#;
    let p = compile_q(q).unwrap().finalize(cutoff()).unwrap();
    assert_eq!(
        p.blocks()[0].from(),
        ["https://example.org/A", "opaque:label"]
    );
    assert_eq!(
        p.walk_predicates()[0].builtin().unwrap().operand(),
        &Value::String("https://example.org/T".into())
    );
    assert_eq!(
        p.walk_predicates()[1].builtin().unwrap().operand(),
        &Value::String("ex:T".into())
    );
    let b = p
        .projection()
        .canonical()
        .payload()
        .field("query")
        .unwrap()
        .field("bounds")
        .unwrap();
    assert_eq!(b.field("type").unwrap(), &V::string("ex:T"));
    for extra in [
        r#", "@context":{"meta":"https://evil/"}"#,
        r#", "walk":{"predicates":[["meta:claim_type","=","absent:T"]]}"#,
        r#", "walk":{"predicates":[["meta:confidence","=","bound:absent"]]}"#,
    ] {
        assert!(compile_q(&query(extra)).is_err());
    }
}
#[test]
fn all_common_operators_compile_bare_and_named() {
    for (op, field, operand) in [
        ("=", "meta:confidence", "1"),
        ("!=", "meta:confidence", "1"),
        (">", "meta:confidence", "0"),
        (">=", "meta:confidence", "0"),
        ("<", "meta:confidence", "1"),
        ("<=", "meta:confidence", "1"),
        ("in", "meta:confidence", "[0,1]"),
        ("not_in", "meta:confidence", "[0,1]"),
        ("contains", "path.meta:claim_id", r#""c""#),
        ("contains_any", "path.meta:claim_id", r#"["c"]"#),
        ("exists", "meta:lineage", "true"),
    ] {
        for named in [false, true] {
            let triple = format!(r#"["{field}","{op}",{operand}]"#);
            let pred = if named {
                format!(r#"{{"name":"test","where":{triple}}}"#)
            } else {
                triple
            };
            let q = query(&format!(r#", "walk":{{"predicates":[{pred}]}}"#));
            assert!(compile_q(&q).is_ok(), "{op}/{named}: {:?}", compile_q(&q));
        }
    }
}
#[test]
fn full_list_validation_and_static_path_type_errors() {
    for predicate in [
        r#"["meta:confidence","in",[0,"bad"]]"#,
        r#"["meta:ext:x","in",[0,"bad"]]"#,
        r#"["path.meta:depth",">",1]"#,
        r#"["meta:depth","contains_any",[1]]"#,
        r#"["meta:grounding_level","=","unknown"]"#,
        r#"["meta:transaction_time",">","2020-01-01T00:00:00.0001Z"]"#,
    ] {
        assert!(
            compile_q(&query(&format!(
                r#", "filter":{{"predicates":[{predicate}]}}"#
            )))
            .is_err(),
            "{predicate}"
        );
    }
}
#[test]
fn independent_filter_existentials_and_path_missing() {
    let p = compile_q(&query(r#", "filter":{"predicates":[["meta:depth","=",1],["meta:depth","=",2],["path.meta:depth","contains",2]]}"#)).unwrap().finalize(cutoff()).unwrap();
    let values = [
        Value::Number(cdb_core::ExactNumber::from_u64(1)),
        Value::Number(cdb_core::ExactNumber::from_u64(2)),
    ];
    for pred in p.filter_predicates() {
        assert!(pred
            .builtin()
            .unwrap()
            .evaluate_filter(&values, pred.phase())
            .unwrap());
    }
    let pred = &p.filter_predicates()[2];
    assert!(pred
        .builtin()
        .unwrap()
        .evaluate_filter(&[Value::Missing, values[1].clone()], pred.phase())
        .unwrap());
}
#[test]
fn requested_cutoff_must_match_capture() {
    let q = r#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1,"as_of":"2026-03-31T01:00:00+01:00"}}"#;
    let d = compile_q(q).unwrap();
    assert_eq!(d.requested_as_of(), Some(cutoff()));
    assert!(d.clone().finalize(cutoff()).is_ok());
    assert!(d
        .finalize(Timestamp::parse("2026-04-01T00:00:00Z").unwrap())
        .is_err());
}
#[test]
fn exact_byte_artifact_identity_and_pinned_profile() {
    let c = artifact("c", CONFIG);
    let q = artifact("q", &query(""));
    let p1 = compile(
        QuerySource::published(&q),
        None,
        &c,
        CompileOptions::default(),
    )
    .unwrap()
    .finalize(cutoff())
    .unwrap();
    let bytes = format!(" {} ", query(""));
    assert!(compile(
        QuerySource {
            bytes: bytes.as_bytes(),
            published: Some(&q)
        },
        None,
        &c,
        CompileOptions::default()
    )
    .is_err());
    let c2 = artifact("c", &format!(" {CONFIG}"));
    let p2 = compile(
        QuerySource::published(&q),
        None,
        &c2,
        CompileOptions::default(),
    )
    .unwrap()
    .finalize(cutoff())
    .unwrap();
    assert_ne!(p1.hash(), p2.hash());
    assert_eq!(
        p1.projection()
            .canonical()
            .payload()
            .field("config")
            .unwrap(),
        p2.projection()
            .canonical()
            .payload()
            .field("config")
            .unwrap()
    );
    let profile = artifact("p", "{}");
    let query = query(",\"profile\":\"p\"");
    assert!(compile(
        QuerySource::inline(query.as_bytes()),
        Some(SelectedProfile {
            selector: "p",
            artifact: &profile
        }),
        &c,
        CompileOptions::default()
    )
    .is_ok());
    // Exact ref pinning is the catalog boundary, not an invented query syntax.
    assert!(compile(
        QuerySource::inline(query.as_bytes()),
        Some(SelectedProfile {
            selector: "different-name",
            artifact: &profile
        }),
        &c,
        CompileOptions::default()
    )
    .is_err());
}
#[test]
fn all_cycles_and_unknown_strategy_capability() {
    for (name, expected) in [
        ("no_repeated_claim", CyclePolicy::NoRepeatedClaim),
        ("allow_repeated_claim", CyclePolicy::AllowRepeatedClaim),
        ("no_repeated_node", CyclePolicy::NoRepeatedNode),
    ] {
        let c = artifact("c", &CONFIG.replace("no_repeated_claim", name));
        let p = compile(
            QuerySource::inline(query("").as_bytes()),
            None,
            &c,
            CompileOptions::default(),
        )
        .unwrap()
        .finalize(cutoff())
        .unwrap();
        assert_eq!(p.cycle_policy(), expected);
    }
    for c in [
        CONFIG.replace("no_repeated_claim", "custom"),
        CONFIG.replace("depth asc", "custom"),
    ] {
        assert_eq!(
            compile(
                QuerySource::inline(query("").as_bytes()),
                None,
                &artifact("c", &c),
                CompileOptions::default()
            )
            .unwrap_err()
            .kind,
            ErrorKind::Unsupported
        );
    }
}
#[test]
fn unused_mapping_registry_hashed_but_required_fails() {
    let config = CONFIG.replace(
        "\"fields\":{}",
        r#""fields":{"meta:ext:x":{"source":"computed","resolver":"fixture.x"}}"#,
    );
    let c = artifact("c", &config);
    assert!(compile(
        QuerySource::inline(query("").as_bytes()),
        None,
        &c,
        CompileOptions::default()
    )
    .is_ok());
    let q = query(r#", "walk":{"predicates":[["meta:ext:x","exists",true]]}"#);
    assert_eq!(
        compile(
            QuerySource::inline(q.as_bytes()),
            None,
            &c,
            CompileOptions::default()
        )
        .unwrap_err()
        .kind,
        ErrorKind::Unsupported
    );
}
#[test]
fn operational_limits_and_nonbinding_hash_invariance() {
    let q = query("");
    let c = artifact("c", CONFIG);
    let small = CompileOptions {
        limits: Limits::new(20, 10, 100, 1000, 2000).unwrap(),
    };
    assert_eq!(
        compile(QuerySource::inline(q.as_bytes()), None, &c, small)
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
    let a = compile(
        QuerySource::inline(q.as_bytes()),
        None,
        &c,
        CompileOptions::default(),
    )
    .unwrap()
    .finalize(cutoff())
    .unwrap();
    let b = compile(
        QuerySource::inline(q.as_bytes()),
        None,
        &c,
        CompileOptions {
            limits: Limits::new(10000, 50, 1000, 10000, 10000).unwrap(),
        },
    )
    .unwrap()
    .finalize(cutoff())
    .unwrap();
    assert_eq!(a.hash(), b.hash());
}
