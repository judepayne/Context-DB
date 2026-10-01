use cdb_backend_fluree::{
    authorized_view::{
        build_reasoner_input, AuthorizedViewManifest, ExactTerm, OntologyProfileDescriptor,
        RdfNodeId, ReasoningDescriptor, SemanticCaptureDescriptor, SourceQuad,
    },
    current_reasoning_profile::classify_current_reasoning_profile,
    ontology_profile_v2::{OntologyProfileLimits, STRUCTURAL_MAPPING_ALGORITHM},
    reasoning_sandbox::{
        normalize_reasoning_overlay, reason_authorized_manifest, PreparedFact, SandboxLimits,
    },
};
use cdb_core::id::ContentHash;
use fluree_db_api::{FlureeBuilder, LedgerState, Novelty};
use fluree_db_core::{GraphDbRef, LedgerSnapshot};
use fluree_db_reasoner::{reason_owl2rl, ReasoningBudget, ReasoningCache, ReasoningOptions};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const G: &str = "urn:graph:p5-6-parity";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_FIRST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first";
const RDF_REST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest";
const RDF_NIL: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil";
const RDFS_SUBCLASS: &str = "http://www.w3.org/2000/01/rdf-schema#subClassOf";
const RDFS_SUBPROPERTY: &str = "http://www.w3.org/2000/01/rdf-schema#subPropertyOf";
const RDFS_DOMAIN: &str = "http://www.w3.org/2000/01/rdf-schema#domain";
const RDFS_RANGE: &str = "http://www.w3.org/2000/01/rdf-schema#range";
const OWL: &str = "http://www.w3.org/2002/07/owl#";
const XSD_NON_NEGATIVE_INTEGER: &str = "http://www.w3.org/2001/XMLSchema#nonNegativeInteger";
const TEST_NAME: &str = "all_inventoried_families_match_direct_and_sealed_manifest_results";

#[derive(Clone)]
struct ParityVector {
    family: String,
    schema: BTreeSet<SourceQuad>,
    data: BTreeSet<SourceQuad>,
}

fn iri(local: &str) -> String {
    if local.starts_with("http://") || local.starts_with("https://") || local.starts_with("urn:") {
        local.to_owned()
    } else {
        format!("urn:p5-6:parity:{local}")
    }
}

fn node(value: impl Into<String>) -> RdfNodeId {
    RdfNodeId::Iri(value.into())
}

fn blank(value: &str) -> RdfNodeId {
    RdfNodeId::ScopedBlankNode(format!("_:fdb-{value}"))
}

fn iri_term(value: impl Into<String>) -> ExactTerm {
    ExactTerm::Iri(value.into())
}

fn blank_term(value: &str) -> ExactTerm {
    ExactTerm::ScopedBlankNode(format!("_:fdb-{value}"))
}

fn quad(subject: RdfNodeId, predicate: impl Into<String>, object: ExactTerm) -> SourceQuad {
    SourceQuad {
        graph: G.into(),
        subject,
        predicate: predicate.into(),
        object,
    }
}

fn iq(subject: &str, predicate: &str, object: &str) -> SourceQuad {
    quad(node(iri(subject)), predicate, iri_term(iri(object)))
}

fn typeq(subject: &str, object: &str) -> SourceQuad {
    iq(subject, RDF_TYPE, object)
}

fn list(prefix: &str, members: &[&str]) -> BTreeSet<SourceQuad> {
    let mut quads = BTreeSet::new();
    for (index, member) in members.iter().enumerate() {
        let cell = format!("{prefix}-{index}");
        quads.insert(quad(blank(&cell), RDF_FIRST, iri_term(iri(member))));
        quads.insert(quad(
            blank(&cell),
            RDF_REST,
            if index + 1 == members.len() {
                iri_term(RDF_NIL)
            } else {
                blank_term(&format!("{prefix}-{}", index + 1))
            },
        ));
    }
    quads
}

fn restriction_schema(
    name: &str,
    property: &str,
    facet: &str,
    value: ExactTerm,
) -> BTreeSet<SourceQuad> {
    BTreeSet::from([
        quad(
            node(iri(name)),
            RDF_TYPE,
            iri_term(format!("{OWL}Restriction")),
        ),
        quad(
            node(iri(name)),
            format!("{OWL}onProperty"),
            iri_term(iri(property)),
        ),
        quad(node(iri(name)), facet, value),
    ])
}

fn vector(family: &str) -> ParityVector {
    let (schema, data) = match family {
        "prp-symp" => (
            BTreeSet::from([typeq(
                "p",
                "http://www.w3.org/2002/07/owl#SymmetricProperty",
            )]),
            BTreeSet::from([iq("a", &iri("p"), "b")]),
        ),
        "prp-trp" => (
            BTreeSet::from([typeq(
                "p",
                "http://www.w3.org/2002/07/owl#TransitiveProperty",
            )]),
            BTreeSet::from([iq("a", &iri("p"), "b"), iq("b", &iri("p"), "c")]),
        ),
        "prp-inv" => (
            BTreeSet::from([iq("forward", &format!("{OWL}inverseOf"), "backward")]),
            BTreeSet::from([iq("a", &iri("forward"), "b")]),
        ),
        "prp-dom" => (
            BTreeSet::from([iq("p", RDFS_DOMAIN, "Class")]),
            BTreeSet::from([iq("subject", &iri("p"), "object")]),
        ),
        "prp-rng" => (
            BTreeSet::from([iq("p", RDFS_RANGE, "Class")]),
            BTreeSet::from([iq("subject", &iri("p"), "object")]),
        ),
        "prp-spo1" => (
            BTreeSet::from([iq("narrow", RDFS_SUBPROPERTY, "broad")]),
            BTreeSet::from([iq("subject", &iri("narrow"), "object")]),
        ),
        "prp-spo2" => {
            let mut schema = BTreeSet::from([quad(
                node(iri("chain")),
                format!("{OWL}propertyChainAxiom"),
                blank_term("chain-0"),
            )]);
            schema.extend(list("chain", &["left", "right"]));
            (
                schema,
                BTreeSet::from([
                    iq("start", &iri("left"), "middle"),
                    iq("middle", &iri("right"), "end"),
                ]),
            )
        }
        "prp-fp" => (
            BTreeSet::from([typeq(
                "p",
                "http://www.w3.org/2002/07/owl#FunctionalProperty",
            )]),
            BTreeSet::from([
                iq("subject", &iri("p"), "object-a"),
                iq("subject", &iri("p"), "object-b"),
            ]),
        ),
        "prp-ifp" => (
            BTreeSet::from([typeq(
                "p",
                "http://www.w3.org/2002/07/owl#InverseFunctionalProperty",
            )]),
            BTreeSet::from([
                iq("subject-a", &iri("p"), "object"),
                iq("subject-b", &iri("p"), "object"),
            ]),
        ),
        "prp-key" => {
            let mut schema = BTreeSet::from([quad(
                node(iri("Class")),
                format!("{OWL}hasKey"),
                blank_term("key-0"),
            )]);
            schema.extend(list("key", &["key-property"]));
            (
                schema,
                BTreeSet::from([
                    typeq("subject-a", "Class"),
                    typeq("subject-b", "Class"),
                    iq("subject-a", &iri("key-property"), "value"),
                    iq("subject-b", &iri("key-property"), "value"),
                ]),
            )
        }
        "cax-sco" => (
            BTreeSet::from([iq("Sub", RDFS_SUBCLASS, "Super")]),
            BTreeSet::from([typeq("subject", "Sub")]),
        ),
        "cax-eqc" => (
            BTreeSet::from([iq("Left", &format!("{OWL}equivalentClass"), "Right")]),
            BTreeSet::from([typeq("subject", "Left")]),
        ),
        "cls-hv1" => (
            restriction_schema(
                "Restriction",
                "p",
                &format!("{OWL}hasValue"),
                iri_term(iri("value")),
            ),
            BTreeSet::from([typeq("subject", "Restriction")]),
        ),
        "cls-hv2" => (
            restriction_schema(
                "Restriction",
                "p",
                &format!("{OWL}hasValue"),
                iri_term(iri("value")),
            ),
            BTreeSet::from([iq("subject", &iri("p"), "value")]),
        ),
        "cls-svf1" => (
            restriction_schema(
                "Restriction",
                "p",
                &format!("{OWL}someValuesFrom"),
                iri_term(iri("Target")),
            ),
            BTreeSet::from([
                iq("subject", &iri("p"), "object"),
                typeq("object", "Target"),
            ]),
        ),
        "cls-avf" => (
            restriction_schema(
                "Restriction",
                "p",
                &format!("{OWL}allValuesFrom"),
                iri_term(iri("Target")),
            ),
            BTreeSet::from([
                typeq("subject", "Restriction"),
                iq("subject", &iri("p"), "object"),
            ]),
        ),
        "cls-int1" => {
            let mut schema = BTreeSet::from([quad(
                node(iri("Intersection")),
                format!("{OWL}intersectionOf"),
                blank_term("intersection-0"),
            )]);
            schema.extend(list("intersection", &["Left", "Right"]));
            (
                schema,
                BTreeSet::from([typeq("subject", "Left"), typeq("subject", "Right")]),
            )
        }
        "cls-int2" => {
            let mut schema = BTreeSet::from([quad(
                node(iri("Intersection")),
                format!("{OWL}intersectionOf"),
                blank_term("intersection-0"),
            )]);
            schema.extend(list("intersection", &["Left", "Right"]));
            (schema, BTreeSet::from([typeq("subject", "Intersection")]))
        }
        "cls-uni" => {
            let mut schema = BTreeSet::from([quad(
                node(iri("Union")),
                format!("{OWL}unionOf"),
                blank_term("union-0"),
            )]);
            schema.extend(list("union", &["Left", "Right"]));
            (schema, BTreeSet::from([typeq("subject", "Right")]))
        }
        "cls-oo" => {
            let mut schema = BTreeSet::from([quad(
                node(iri("Enumeration")),
                format!("{OWL}oneOf"),
                blank_term("one-of-0"),
            )]);
            schema.extend(list("one-of", &["member-a", "member-b"]));
            (schema, BTreeSet::from([typeq("trigger", "Trigger")]))
        }
        "cls-maxc2" => (
            restriction_schema(
                "Restriction",
                "p",
                &format!("{OWL}maxCardinality"),
                ExactTerm::Literal {
                    lexical: "1".into(),
                    datatype: XSD_NON_NEGATIVE_INTEGER.into(),
                    language: None,
                },
            ),
            BTreeSet::from([
                typeq("subject", "Restriction"),
                iq("subject", &iri("p"), "object-a"),
                iq("subject", &iri("p"), "object-b"),
            ]),
        ),
        "cls-maxqc" => {
            let mut schema = restriction_schema(
                "Restriction",
                "p",
                &format!("{OWL}maxQualifiedCardinality"),
                ExactTerm::Literal {
                    lexical: "1".into(),
                    datatype: XSD_NON_NEGATIVE_INTEGER.into(),
                    language: None,
                },
            );
            schema.insert(iq("Restriction", &format!("{OWL}onClass"), "Qualified"));
            (
                schema,
                BTreeSet::from([
                    typeq("subject", "Restriction"),
                    iq("subject", &iri("p"), "object-a"),
                    iq("subject", &iri("p"), "object-b"),
                    typeq("object-a", "Qualified"),
                    typeq("object-b", "Qualified"),
                ]),
            )
        }
        "owl:sameAs" => (
            BTreeSet::new(),
            BTreeSet::from([
                iq("same-b", &format!("{OWL}sameAs"), "same-a"),
                iq("same-c", &format!("{OWL}sameAs"), "same-a"),
                iq("same-b", &iri("p"), "object"),
                iq("subject", &iri("p"), "same-c"),
            ]),
        ),
        _ => panic!("unregistered parity family: {family}"),
    };
    ParityVector {
        family: family.to_owned(),
        schema,
        data,
    }
}

fn manifest(vector: &ParityVector) -> AuthorizedViewManifest {
    let capture = SemanticCaptureDescriptor {
        ledger: format!("ctxql/p5-6-parity-{}:main", vector.family.replace(':', "-")),
        requested_as_of: "t:1".into(),
        t: 1,
        commit_cid: format!("bafy-p5-6-parity-{}", vector.family.replace(':', "-")),
    };
    let profile =
        classify_current_reasoning_profile(&vector.schema, OntologyProfileLimits::default())
            .unwrap();
    let input =
        build_reasoner_input(&capture, &vector.data, &profile.reasoner_projection.quads).unwrap();
    AuthorizedViewManifest::seal_profiled_v2(
        capture,
        ReasoningDescriptor {
            schema_source: G.into(),
            follow_owl_imports: false,
            schema_graphs: BTreeSet::from([G.into()]),
        },
        vector.data.clone(),
        vector.schema.clone(),
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
    )
}

fn asserted_facts(manifest: &AuthorizedViewManifest) -> BTreeSet<PreparedFact> {
    manifest
        .reasoner_input_quads
        .iter()
        .map(|quad| PreparedFact {
            subject: quad.subject.as_iri().unwrap().to_owned(),
            predicate: quad.predicate.clone(),
            object: quad.object.clone(),
        })
        .collect()
}

async fn direct_reason(
    manifest: &AuthorizedViewManifest,
) -> (
    LedgerState,
    std::sync::Arc<fluree_db_reasoner::ReasoningResult>,
) {
    let turtle = manifest
        .reasoner_input_quads
        .iter()
        .map(SourceQuad::turtle)
        .collect::<Vec<_>>()
        .join("\n");
    let fluree = FlureeBuilder::memory().build_memory();
    let direct_ledger = format!("{}-direct", manifest.capture.ledger);
    let ledger = fluree
        .stage_owned(LedgerState::new(
            LedgerSnapshot::genesis(&direct_ledger),
            Novelty::new(0),
        ))
        .upsert_turtle(&turtle)
        .execute()
        .await
        .unwrap()
        .ledger;
    let result = reason_owl2rl(
        GraphDbRef::new(&ledger.snapshot, 0, ledger.novelty.as_ref(), ledger.t()),
        &ReasoningOptions::with_budget(ReasoningBudget::unlimited()),
        &ReasoningCache::new(1),
    )
    .await
    .unwrap();
    (ledger, result)
}

fn canonicalize_equality(facts: BTreeSet<PreparedFact>) -> BTreeSet<PreparedFact> {
    const SAME_AS: &str = "http://www.w3.org/2002/07/owl#sameAs";

    fn root(parents: &BTreeMap<String, String>, value: &str) -> String {
        let mut current = value;
        while let Some(parent) = parents.get(current) {
            if parent == current {
                break;
            }
            current = parent;
        }
        current.to_owned()
    }

    let mut parents = BTreeMap::new();
    for fact in &facts {
        if fact.predicate != SAME_AS {
            continue;
        }
        let ExactTerm::Iri(object) = &fact.object else {
            continue;
        };
        parents
            .entry(fact.subject.clone())
            .or_insert_with(|| fact.subject.clone());
        parents
            .entry(object.clone())
            .or_insert_with(|| object.clone());
    }
    loop {
        let mut changed = false;
        for fact in &facts {
            if fact.predicate != SAME_AS {
                continue;
            }
            let ExactTerm::Iri(object) = &fact.object else {
                continue;
            };
            let left = root(&parents, &fact.subject);
            let right = root(&parents, object);
            let canonical = left.min(right);
            for value in [&fact.subject, object] {
                let actual = root(&parents, value);
                if actual != canonical {
                    parents.insert(actual, canonical.clone());
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut normalized = BTreeSet::new();
    let mut components: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for value in parents.keys() {
        components
            .entry(root(&parents, value))
            .or_default()
            .insert(value.clone());
    }
    for fact in facts {
        if fact.predicate == SAME_AS {
            continue;
        }
        let subject = root(&parents, &fact.subject);
        let object = match fact.object {
            ExactTerm::Iri(value) => ExactTerm::Iri(root(&parents, &value)),
            other => other,
        };
        normalized.insert(PreparedFact {
            subject,
            predicate: fact.predicate,
            object,
        });
    }
    for (canonical, members) in components {
        for member in members {
            normalized.insert(PreparedFact {
                subject: canonical.clone(),
                predicate: SAME_AS.into(),
                object: ExactTerm::Iri(member),
            });
        }
    }
    normalized
}

fn inventory() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/conformance/p5_6/direct-reasoner-inventory.json"
    ))
    .unwrap()
}

fn registry() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/conformance/p5_6/production-parity-vectors.json"
    ))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_inventoried_families_match_direct_and_sealed_manifest_results() {
    let inventory = inventory();
    let registry = registry();
    assert_eq!(
        registry["schema"],
        "ctxql.p5-6-production-parity-vectors/v1"
    );
    let inventory_rows = inventory["rule_families"].as_array().unwrap();
    let registry_rows = registry["vectors"].as_array().unwrap();
    let inventory_families = inventory_rows
        .iter()
        .map(|row| row["canonical"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    let registry_families = registry_rows
        .iter()
        .map(|row| row["family"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(registry_families, inventory_families);

    let mut executed = BTreeSet::new();
    for row in registry_rows {
        let family = row["family"].as_str().unwrap();
        let inventory_row = inventory_rows
            .iter()
            .find(|candidate| candidate["canonical"] == family)
            .unwrap();
        assert_eq!(row["native_oracle"], inventory_row["native_oracle"]);
        assert_eq!(row["production_vector"], inventory_row["production_vector"]);
        assert_eq!(row["fixture_selector"], family);
        assert_eq!(row["test_target"], "p5_6_production_parity");
        assert_eq!(row["test_name"], TEST_NAME);

        let vector = vector(family);
        let manifest = manifest(&vector);
        manifest.validate().unwrap();
        let asserted = asserted_facts(&manifest);
        let (ledger, direct_result) = direct_reason(&manifest).await;
        let mut direct = normalize_reasoning_overlay(&ledger.snapshot, &direct_result).unwrap();
        let production = reason_authorized_manifest(&manifest, SandboxLimits::default())
            .await
            .unwrap();
        let mut sealed = production.inferred_facts;
        direct.retain(|fact| !asserted.contains(fact));
        sealed.retain(|fact| !asserted.contains(fact));
        let direct = canonicalize_equality(direct);
        let sealed = canonicalize_equality(sealed);
        assert_eq!(
            sealed, direct,
            "direct and sealed-manifest inferred sets differ for {family}"
        );
        assert!(
            !sealed.is_empty(),
            "parity vector inferred nothing for {family}: direct={:?}; sealed={:?}",
            direct_result.diagnostics.rules_fired,
            production.diagnostics.rules_fired
        );

        let diagnostic = row["diagnostic_key"].as_str().unwrap();
        let direct_fired = direct_result
            .diagnostics
            .rules_fired
            .get(diagnostic)
            .copied()
            .unwrap_or(0);
        let sealed_fired = production
            .diagnostics
            .rules_fired
            .get(diagnostic)
            .copied()
            .unwrap_or(0);
        if row["diagnostic_required"].as_bool().unwrap() {
            assert!(
                direct_fired > 0,
                "direct diagnostic {diagnostic} did not fire for {family}: {:?}",
                direct_result.diagnostics.rules_fired
            );
            assert!(
                sealed_fired > 0,
                "sealed diagnostic {diagnostic} did not fire for {family}: {:?}",
                production.diagnostics.rules_fired
            );
        } else {
            assert_eq!(direct_fired, sealed_fired);
        }
        assert!(executed.insert(row["production_vector"].as_str().unwrap()));
    }

    let registered = inventory_rows
        .iter()
        .map(|row| row["production_vector"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(executed, registered);
    let production_vectors = executed.into_iter().collect::<Vec<_>>();
    let coverage_root = ContentHash::of_bytes(production_vectors.join("\n").as_bytes());
    println!(
        "P5_6_PARITY_COVERAGE {}",
        serde_json::to_string(&json!({
            "coverage_root": coverage_root.as_str(),
            "production_vectors": production_vectors,
        }))
        .unwrap()
    );
}
