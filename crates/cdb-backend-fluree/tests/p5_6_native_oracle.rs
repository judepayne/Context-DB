mod support;

use cdb_backend_fluree::{
    authorized_view::{
        build_reasoner_input, AuthorizedViewManifest, ExactTerm, OntologyProfileDescriptor,
        RdfNodeId, ReasoningDescriptor, SemanticCaptureDescriptor, SourceQuad,
    },
    ontology_profile_v2::{
        classify_ontology_bundle_v2, OntologyProfileLimits, STRUCTURAL_MAPPING_ALGORITHM,
    },
    reasoning_sandbox::{reason_authorized_manifest, SandboxLimits},
};
use cdb_core::id::ContentHash;
use fluree_db_api::{Fluree, FlureeBuilder, LedgerState, Novelty};
use fluree_db_core::{FlakeValue, GraphDbRef, LedgerSnapshot};
use fluree_db_reasoner::{
    reason_owl2rl, ReasoningBudget, ReasoningCache, ReasoningOptions, ReasoningResult,
    KNOWN_RULE_NAMES,
};
use serde_json::Value;
use std::{collections::BTreeSet, time::Duration};

const EX: &str = "http://example.org/";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const OWL_SAME_AS: &str = "http://www.w3.org/2002/07/owl#sameAs";

fn genesis(id: &str) -> LedgerState {
    LedgerState::new(LedgerSnapshot::genesis(id), Novelty::new(0))
}

async fn load(id: &str, turtle: &str) -> (Fluree, LedgerState) {
    let fluree = FlureeBuilder::memory().build_memory();
    let ledger = fluree
        .stage_owned(genesis(id))
        .upsert_turtle(turtle)
        .execute()
        .await
        .expect("native oracle Turtle must load")
        .ledger;
    (fluree, ledger)
}

async fn reason(
    ledger: &LedgerState,
    enabled_rules: &[&str],
    budget: ReasoningBudget,
) -> std::sync::Arc<ReasoningResult> {
    let options = ReasoningOptions {
        budget,
        enabled_rules: enabled_rules.iter().map(|s| (*s).to_owned()).collect(),
    };
    reason_owl2rl(
        GraphDbRef::new(&ledger.snapshot, 0, ledger.novelty.as_ref(), ledger.t()),
        &options,
        &ReasoningCache::new(1),
    )
    .await
    .expect("direct native reasoner")
}

fn ref_facts(ledger: &LedgerState, result: &ReasoningResult) -> BTreeSet<(String, String, String)> {
    result
        .overlay
        .flakes_spot()
        .iter()
        .filter_map(|flake| {
            let FlakeValue::Ref(object) = &flake.o else {
                return None;
            };
            Some((
                ledger.snapshot.decode_sid(&flake.s)?,
                ledger.snapshot.decode_sid(&flake.p)?,
                ledger.snapshot.decode_sid(object)?,
            ))
        })
        .collect()
}

fn has_ref(facts: &BTreeSet<(String, String, String)>, s: &str, p: &str, o: &str) -> bool {
    facts.contains(&(format!("{EX}{s}"), p.to_owned(), format!("{EX}{o}")))
}

fn assert_rule_fired(result: &ReasoningResult, rule: &str) {
    assert!(
        result
            .diagnostics
            .rules_fired
            .get(rule)
            .copied()
            .unwrap_or(0)
            > 0,
        "expected canonical diagnostic key {rule}; got {:?}",
        result.diagnostics.rules_fired
    );
}

#[test]
fn inventory_is_revision_bound_and_exactly_matches_public_rule_names() {
    let inventory: Value = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/p5_6/direct-reasoner-inventory.json"
    ))
    .expect("valid inventory JSON");
    assert_eq!(
        inventory["pinned_source"]["git_revision"],
        "603974fad5c13efed9d147d214d613849fb43c73"
    );
    assert_eq!(inventory["pinned_source"]["package_version"], "4.2.0");

    let inventoried: Vec<&str> = inventory["known_rule_names"]
        .as_array()
        .expect("known_rule_names array")
        .iter()
        .map(|v| v.as_str().expect("rule name string"))
        .collect();
    assert_eq!(inventoried.as_slice(), KNOWN_RULE_NAMES);

    let source_files = inventory["source_files"]
        .as_object()
        .expect("source hash map");
    for (required, expected) in [
        (
            "fluree-db-reasoner/src/lib.rs",
            "d03f7f6833d632fe363c4e17e30b1e30837bc67c9635b3fdc64c3ab0ac22e2bf",
        ),
        (
            "fluree-db-reasoner/src/fixpoint.rs",
            "7c5f6695a179bf7badd01e282c1d25bc4b83222b4fc13f61594f750dffa65b8b",
        ),
        (
            "fluree-db-reasoner/src/ontology_rl.rs",
            "7bc31b7755620df5bb7580a424a92681d464b6dd6765440ace0f30d7815f83de",
        ),
        (
            "fluree-db-reasoner/src/restrictions.rs",
            "f57322ac07f43aca5a01b6ffc807ace3b0110eba210116fda087b95d3c706b86",
        ),
        (
            "fluree-db-reasoner/src/rdf_list.rs",
            "8d44df30e4e6cce965ecac64437b4bfe85b5a91d3d8d511d9317eac4fddeb3f2",
        ),
    ] {
        assert_eq!(
            source_files[required].as_str(),
            Some(expected),
            "{required}"
        );
    }

    let families = inventory["rule_families"].as_array().expect("families");
    let canonical: BTreeSet<_> = families
        .iter()
        .filter_map(|family| family["canonical"].as_str())
        .collect();
    for rule in KNOWN_RULE_NAMES {
        let aliases = inventory["aliases"].as_object().expect("aliases");
        let implementation = aliases.get(*rule).and_then(Value::as_str).unwrap_or(rule);
        assert!(canonical.contains(implementation), "unbound rule {rule}");
    }
    for family in families {
        assert!(family["native_oracle"]
            .as_str()
            .is_some_and(|v| !v.is_empty()));
        assert!(family["production_vector"]
            .as_str()
            .is_some_and(|v| !v.is_empty()));
    }
}

#[tokio::test]
async fn direct_and_authorized_manifest_results_match() {
    const RDFS_SUBPROPERTY: &str = "http://www.w3.org/2000/01/rdf-schema#subPropertyOf";
    const OWL_ONTOLOGY: &str = "http://www.w3.org/2002/07/owl#Ontology";
    let turtle = r#"
@prefix ex: <http://example.org/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
ex:narrow rdfs:subPropertyOf ex:broad .
ex:alice ex:narrow ex:bob .
"#;
    let (_fluree, ledger) = load("ctxql/p5-6-direct-production-parity:main", turtle).await;
    let native = reason(&ledger, &[], ReasoningBudget::unlimited()).await;
    let native_facts = ref_facts(&ledger, &native);
    let expected = (
        format!("{EX}alice"),
        format!("{EX}broad"),
        format!("{EX}bob"),
    );
    assert!(native_facts.contains(&expected));

    let graph = "urn:graph:parity";
    let quad = |subject: &str, predicate: &str, object: &str| SourceQuad {
        graph: graph.into(),
        subject: RdfNodeId::Iri(subject.into()),
        predicate: predicate.into(),
        object: ExactTerm::Iri(object.into()),
    };
    let schema = BTreeSet::from([
        quad(graph, RDF_TYPE, OWL_ONTOLOGY),
        quad(
            &format!("{EX}narrow"),
            RDFS_SUBPROPERTY,
            &format!("{EX}broad"),
        ),
    ]);
    let data = BTreeSet::from([quad(
        &format!("{EX}alice"),
        &format!("{EX}narrow"),
        &format!("{EX}bob"),
    )]);
    let capture = SemanticCaptureDescriptor {
        ledger: "ctxql/p5-6-direct-production-parity:main".into(),
        requested_as_of: "t:1".into(),
        t: 1,
        commit_cid: "bafy-p5-6-direct-production-parity".into(),
    };
    let profile = classify_ontology_bundle_v2(&schema, OntologyProfileLimits::default()).unwrap();
    let input = build_reasoner_input(&capture, &data, &profile.reasoner_projection.quads).unwrap();
    let manifest = AuthorizedViewManifest::seal_profiled_v2(
        capture,
        ReasoningDescriptor {
            schema_source: graph.into(),
            follow_owl_imports: false,
            schema_graphs: BTreeSet::from([graph.into()]),
        },
        data,
        schema,
        input,
        STRUCTURAL_MAPPING_ALGORITHM.into(),
        profile.limits_identity.clone(),
        BTreeSet::new(),
        ContentHash::of_bytes(b"p5-6-parity-config"),
        OntologyProfileDescriptor {
            identity: profile.identity.into(),
            full_bundle_root: profile.full_bundle_root,
            result_root: profile.result_root,
        },
        ContentHash::of_bytes(b"p5-6-parity-policy"),
        "ctxql-p5-6-complete/v1",
    );
    let manifest = support::seal_for_current_reasoner(&manifest);
    let production = reason_authorized_manifest(&manifest, SandboxLimits::default())
        .await
        .unwrap();
    let production_facts = production
        .inferred_iri_triples
        .iter()
        .filter(|(_, predicate, _)| predicate == &expected.1)
        .cloned()
        .collect::<BTreeSet<_>>();
    let native_facts = native_facts
        .into_iter()
        .filter(|(_, predicate, _)| predicate == &expected.1)
        .collect::<BTreeSet<_>>();
    assert_eq!(production_facts, native_facts);
}

#[tokio::test]
async fn direct_all_rules_oracle_covers_every_canonical_family() {
    let turtle = r#"
@prefix ex: <http://example.org/> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .

ex:sym a owl:SymmetricProperty . ex:a ex:sym ex:b .
ex:tr a owl:TransitiveProperty . ex:a ex:tr ex:b . ex:b ex:tr ex:c .
ex:forward owl:inverseOf ex:backward . ex:a ex:forward ex:b .
ex:domainP rdfs:domain ex:Domain . ex:domainSubject ex:domainP "literal" .
ex:rangeP rdfs:range ex:Range . ex:rangeSubject ex:rangeP ex:rangeObject . ex:rangeLiteral ex:rangeP "literal" .
ex:subP rdfs:subPropertyOf ex:superP . ex:literalSubject ex:subP "copied exactly"@en .

ex:chain owl:propertyChainAxiom _:chain1 .
_:chain1 rdf:first ex:chainA ; rdf:rest _:chain2 .
_:chain2 rdf:first _:inverseMember ; rdf:rest _:chain3 .
_:chain3 rdf:first ex:chainC ; rdf:rest rdf:nil .
_:inverseMember owl:inverseOf ex:chainB .
ex:chainStart ex:chainA ex:chainMid1 . ex:chainMid2 ex:chainB ex:chainMid1 . ex:chainMid2 ex:chainC ex:chainEnd .

ex:functional a owl:FunctionalProperty . ex:fpS ex:functional ex:fpO1, ex:fpO2 .
ex:inverseFunctional a owl:InverseFunctionalProperty . ex:ifpS1 ex:inverseFunctional ex:ifpO . ex:ifpS2 ex:inverseFunctional ex:ifpO .
ex:KeyClass owl:hasKey _:key1 . _:key1 rdf:first ex:keyP ; rdf:rest rdf:nil .
ex:keyS1 a ex:KeyClass ; ex:keyP ex:keyValue . ex:keyS2 a ex:KeyClass ; ex:keyP ex:keyValue .

ex:Sub rdfs:subClassOf ex:Super . ex:subInstance a ex:Sub .
ex:EqA owl:equivalentClass ex:EqB . ex:eqInstance a ex:EqA .

ex:HasValue a owl:Restriction ; owl:onProperty ex:status ; owl:hasValue ex:Active .
ex:hvForward ex:status ex:Active . ex:hvBackward a ex:HasValue .
ex:Some a owl:Restriction ; owl:onProperty ex:child ; owl:someValuesFrom ex:Target .
ex:svfSubject ex:child ex:svfObject . ex:svfObject a ex:Target .
ex:SomeInverse a owl:Restriction ; owl:onProperty _:invProp ; owl:someValuesFrom ex:Target .
_:invProp owl:inverseOf ex:parent . ex:svfInverseObject ex:parent ex:svfInverseSubject . ex:svfInverseObject a ex:Target .
ex:All a owl:Restriction ; owl:onProperty ex:allP ; owl:allValuesFrom ex:AllTarget .
ex:avfSubject a ex:All ; ex:allP ex:avfObject .

ex:Intersection owl:intersectionOf _:int1 . _:int1 rdf:first ex:I1 ; rdf:rest _:int2 . _:int2 rdf:first ex:I2 ; rdf:rest rdf:nil .
ex:intForward a ex:I1, ex:I2 . ex:intBackward a ex:Intersection .
ex:Nested owl:intersectionOf _:nested1 . _:nested1 rdf:first ex:Some ; rdf:rest _:nested2 . _:nested2 rdf:first ex:Marker ; rdf:rest rdf:nil .
ex:svfSubject a ex:Marker .
ex:Union owl:unionOf _:union1 . _:union1 rdf:first ex:U1 ; rdf:rest _:union2 . _:union2 rdf:first ex:U2 ; rdf:rest rdf:nil . ex:unionInstance a ex:U2 .
ex:Enumeration owl:oneOf _:one1 . _:one1 rdf:first ex:enum1 ; rdf:rest _:one2 . _:one2 rdf:first ex:enum2 ; rdf:rest rdf:nil .

ex:MaxOne a owl:Restriction ; owl:onProperty ex:maxP ; owl:maxCardinality 1 .
ex:maxSubject a ex:MaxOne ; ex:maxP ex:maxO1, ex:maxO2 .
ex:MaxQualified a owl:Restriction ; owl:onProperty ex:maxQP ; owl:maxQualifiedCardinality 1 ; owl:onClass ex:Qualified .
ex:maxQSubject a ex:MaxQualified ; ex:maxQP ex:maxQO1, ex:maxQO2 . ex:maxQO1 a ex:Qualified . ex:maxQO2 a ex:Qualified .

ex:sameB owl:sameAs ex:sameA . ex:sameC owl:sameAs ex:sameA . ex:sameB ex:canonicalP ex:canonicalO . ex:canonicalS ex:canonicalP ex:sameC .
"#;
    let (_fluree, ledger) = load("ctxql/p5-6-native-all:main", turtle).await;
    let result = reason(&ledger, &[], ReasoningBudget::unlimited()).await;
    assert!(!result.diagnostics.capped);
    let facts = ref_facts(&ledger, &result);

    for (rule, s, p, o) in [
        ("prp-symp", "b", format!("{EX}sym"), "a"),
        ("prp-trp", "a", format!("{EX}tr"), "c"),
        ("prp-inv", "b", format!("{EX}backward"), "a"),
        ("prp-dom", "domainSubject", RDF_TYPE.into(), "Domain"),
        ("prp-rng", "rangeObject", RDF_TYPE.into(), "Range"),
        ("prp-spo2", "chainStart", format!("{EX}chain"), "chainEnd"),
        ("cax-sco", "subInstance", RDF_TYPE.into(), "Super"),
        ("cax-eqc", "eqInstance", RDF_TYPE.into(), "EqB"),
        ("cls-hv2", "hvForward", RDF_TYPE.into(), "HasValue"),
        ("cls-hv1", "hvBackward", format!("{EX}status"), "Active"),
        ("cls-svf1", "svfSubject", RDF_TYPE.into(), "Some"),
        (
            "cls-svf1",
            "svfInverseSubject",
            RDF_TYPE.into(),
            "SomeInverse",
        ),
        ("cls-avf", "avfObject", RDF_TYPE.into(), "AllTarget"),
        ("cls-int1", "intForward", RDF_TYPE.into(), "Intersection"),
        ("cls-int2", "intBackward", RDF_TYPE.into(), "I1"),
        ("cls-uni", "unionInstance", RDF_TYPE.into(), "Union"),
        ("cls-oo", "enum1", RDF_TYPE.into(), "Enumeration"),
        ("cls-int1", "svfSubject", RDF_TYPE.into(), "Nested"),
    ] {
        assert!(
            has_ref(&facts, s, &p, o),
            "missing {rule} result ({s}, {p}, {o})"
        );
        assert_rule_fired(&result, rule);
    }

    for rule in ["prp-fp", "prp-ifp", "prp-key", "cls-maxc2", "cls-maxqc"] {
        assert_rule_fired(&result, rule);
    }
    assert_rule_fired(&result, "eq-union");

    let literal_copy = result.overlay.flakes_spot().iter().any(|flake| {
        ledger.snapshot.decode_sid(&flake.s).as_deref() == Some("http://example.org/literalSubject")
            && ledger.snapshot.decode_sid(&flake.p).as_deref() == Some("http://example.org/superP")
            && matches!(&flake.o, FlakeValue::String(v) if v == "copied exactly")
    });
    assert!(literal_copy, "prp-spo1 must copy a literal object exactly");
    assert_rule_fired(&result, "prp-spo1");

    let same_as: BTreeSet<_> = facts
        .iter()
        .filter(|(_, p, _)| p == OWL_SAME_AS)
        .cloned()
        .collect();
    assert!(same_as
        .iter()
        .any(|(s, _, o)| s.ends_with("sameA") && o.ends_with("sameB")));
    assert!(same_as
        .iter()
        .any(|(s, _, o)| s.ends_with("sameA") && o.ends_with("sameC")));
    assert!(
        !same_as.contains(&(
            format!("{EX}sameB"),
            OWL_SAME_AS.into(),
            format!("{EX}sameC")
        )),
        "native equality output is a canonical star, not a full clique"
    );
}

#[tokio::test]
async fn aliases_enable_the_canonical_implementation_and_diagnostic_key() {
    let eq = r#"
@prefix ex: <http://example.org/> . @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> . ex:A owl:equivalentClass ex:B . ex:x rdf:type ex:A .
"#;
    for alias in ["cax-eqc1", "cax-eqc2"] {
        let (_f, ledger) = load(&format!("ctxql/p5-6-{alias}:main"), eq).await;
        let result = reason(&ledger, &[alias], ReasoningBudget::unlimited()).await;
        assert_rule_fired(&result, "cax-eqc");
        assert!(!result.diagnostics.rules_fired.contains_key(alias));
    }

    let maxq = r#"
@prefix ex: <http://example.org/> . @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
ex:R a owl:Restriction ; owl:onProperty ex:p ; owl:maxQualifiedCardinality 1 ; owl:onClass ex:C .
ex:x a ex:R ; ex:p ex:a, ex:b . ex:a a ex:C . ex:b a ex:C .
"#;
    for alias in ["cls-maxqc3", "cls-maxqc4"] {
        let (_f, ledger) = load(&format!("ctxql/p5-6-{alias}:main"), maxq).await;
        let result = reason(&ledger, &[alias], ReasoningBudget::unlimited()).await;
        assert_rule_fired(&result, "cls-maxqc");
        assert!(!result.diagnostics.rules_fired.contains_key(alias));
    }
}

#[tokio::test]
async fn cardinality_integer_family_forms_match_the_native_long_materializer() {
    let datatypes = [
        "integer",
        "long",
        "int",
        "short",
        "byte",
        "unsignedLong",
        "unsignedInt",
        "unsignedShort",
        "unsignedByte",
        "nonNegativeInteger",
        "positiveInteger",
    ];
    let mut turtle = String::from(
        "@prefix ex: <http://example.org/> .\n@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n@prefix owl: <http://www.w3.org/2002/07/owl#> .\n@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n",
    );
    for (index, datatype) in datatypes.into_iter().enumerate() {
        turtle.push_str(&format!(
            "ex:R{index} a owl:Restriction ; owl:onProperty ex:p{index} ; owl:maxCardinality \"1\"^^xsd:{datatype} .\nex:s{index} a ex:R{index} ; ex:p{index} ex:o{index}a, ex:o{index}b .\n"
        ));
    }
    let (_fluree, ledger) = load("ctxql/p5-6-cardinality-family:main", &turtle).await;
    let result = reason(&ledger, &[], ReasoningBudget::unlimited()).await;
    assert_rule_fired(&result, "cls-maxc2");
    let facts = ref_facts(&ledger, &result);
    for index in 0..datatypes.len() {
        let left = format!("{EX}o{index}a");
        let right = format!("{EX}o{index}b");
        assert!(
            facts.contains(&(left.clone(), OWL_SAME_AS.into(), right.clone()))
                || facts.contains(&(right, OWL_SAME_AS.into(), left)),
            "native max-cardinality-one did not consume datatype index {index}"
        );
    }
}

#[tokio::test]
async fn unsupported_neighbors_are_native_non_entailments() {
    let turtle = r#"
@prefix ex: <http://example.org/> . @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
ex:p owl:equivalentProperty ex:q . ex:s ex:p ex:o .
ex:Complement owl:complementOf ex:C . ex:x a ex:C .
ex:C owl:disjointWith ex:D . ex:x a ex:D .
ex:LiteralHV a owl:Restriction ; owl:onProperty ex:value ; owl:hasValue "literal" . ex:l ex:value "literal" .
ex:LiteralEnum owl:oneOf _:le . _:le rdf:first "literal" ; rdf:rest rdf:nil .
ex:LiteralKey owl:hasKey _:lk . _:lk rdf:first ex:key ; rdf:rest rdf:nil . ex:k1 a ex:LiteralKey ; ex:key "same" . ex:k2 a ex:LiteralKey ; ex:key "same" .
ex:Min a owl:Restriction ; owl:onProperty ex:m ; owl:minCardinality 1 .
ex:Exact a owl:Restriction ; owl:onProperty ex:m ; owl:cardinality 1 .
ex:MaxZero a owl:Restriction ; owl:onProperty ex:m ; owl:maxCardinality 0 .
ex:MaxTwo a owl:Restriction ; owl:onProperty ex:m ; owl:maxCardinality 2 .
"#;
    let (_f, ledger) = load("ctxql/p5-6-unsupported:main", turtle).await;
    let result = reason(&ledger, &[], ReasoningBudget::unlimited()).await;
    let facts = ref_facts(&ledger, &result);
    assert!(!has_ref(&facts, "s", &format!("{EX}q"), "o"));
    assert!(!has_ref(&facts, "l", RDF_TYPE, "LiteralHV"));
    assert!(!facts.iter().any(|(s, p, o)| {
        p == OWL_SAME_AS
            && ((s.ends_with("k1") && o.ends_with("k2"))
                || (s.ends_with("k2") && o.ends_with("k1")))
    }));
    for unsupported in ["equivalentProperty", "complementOf", "disjointWith"] {
        assert!(
            !result.diagnostics.rules_fired.contains_key(unsupported),
            "unsupported vocabulary must not imply a rule family"
        );
    }
}

#[tokio::test]
async fn diagnostics_fact_and_memory_budget_boundaries_are_characterized() {
    let turtle = r#"
@prefix ex: <http://example.org/> . @prefix owl: <http://www.w3.org/2002/07/owl#> .
ex:p a owl:TransitiveProperty . ex:a ex:p ex:b . ex:b ex:p ex:c . ex:c ex:p ex:d .
"#;
    let (_f, ledger) = load("ctxql/p5-6-budget:main", turtle).await;
    let capped = reason(
        &ledger,
        &[],
        ReasoningBudget::new(Duration::from_secs(30), 0, usize::MAX),
    )
    .await;
    assert!(capped.diagnostics.capped);
    assert_eq!(capped.diagnostics.capped_reason.as_deref(), Some("facts"));
    assert_eq!(
        capped.diagnostics.iterations, 1,
        "the fact budget is checked during the first iteration"
    );
    assert_eq!(
        capped.diagnostics.facts_derived, 1,
        "4.2.1 checks the projected derived count after each dispatched delta fact"
    );
    assert_rule_fired(&capped, "prp-trp");

    let zero_memory = reason(
        &ledger,
        &[],
        ReasoningBudget::new(Duration::from_secs(30), usize::MAX, 0),
    )
    .await;
    assert!(zero_memory.diagnostics.capped);
    assert_eq!(
        zero_memory.diagnostics.capped_reason.as_deref(),
        Some("memory")
    );
    assert_eq!(zero_memory.diagnostics.iterations, 1);
    assert_eq!(
        zero_memory.diagnostics.facts_derived, 1,
        "4.2.1 enforces memory after each dispatched delta fact at the same one-candidate boundary"
    );
    let unlimited = reason(&ledger, &[], ReasoningBudget::unlimited()).await;
    let memory_capped_facts = ref_facts(&ledger, &zero_memory);
    let unlimited_facts = ref_facts(&ledger, &unlimited);
    assert!(
        memory_capped_facts.is_subset(&unlimited_facts) && memory_capped_facts != unlimited_facts,
        "the enforced zero-memory boundary must truncate this transitive closure"
    );
}
