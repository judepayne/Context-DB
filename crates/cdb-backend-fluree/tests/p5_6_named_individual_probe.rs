mod support;

use cdb_backend_fluree::{
    authorized_view::{
        build_reasoner_input, AuthorizedViewManifest, ExactTerm, OntologyProfileDescriptor,
        RdfNodeId, ReasoningDescriptor, SemanticCaptureDescriptor, SourceQuad,
    },
    ontology_profile_v2::{
        analyze_ontology_bundle_v2, classify_ontology_bundle_v2, OntologyIssueClass,
        OntologyProfileLimits, STRUCTURAL_MAPPING_ALGORITHM,
    },
    reasoning_sandbox::{reason_authorized_manifest, PreparedFact, SandboxLimits},
};
use cdb_core::id::ContentHash;
use fluree_db_api::{FlureeBuilder, LedgerState, Novelty};
use fluree_db_core::{
    comparator::IndexType,
    range::{RangeMatch, RangeTest},
    FlakeValue, GraphDbRef, LedgerSnapshot,
};
use fluree_db_reasoner::{
    reason_owl2rl, ReasoningBudget, ReasoningCache, ReasoningOptions, ReasoningResult,
};
use std::collections::{BTreeMap, BTreeSet};

const EX: &str = "http://example.org/";
const SCHEMA_GRAPH: &str = "urn:graph:named-individual-probe-schema";
const DATA_GRAPH: &str = "urn:graph:named-individual-probe-data";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDFS_SUBCLASS: &str = "http://www.w3.org/2000/01/rdf-schema#subClassOf";
const OWL_ONTOLOGY: &str = "http://www.w3.org/2002/07/owl#Ontology";
const OWL_INVERSE_OF: &str = "http://www.w3.org/2002/07/owl#inverseOf";
const OWL_NAMED_INDIVIDUAL: &str = "http://www.w3.org/2002/07/owl#NamedIndividual";

type IriTriple = (String, String, String);

fn genesis(id: &str) -> LedgerState {
    LedgerState::new(LedgerSnapshot::genesis(id), Novelty::new(0))
}

async fn direct_ledger(id: &str, include_declaration: bool) -> LedgerState {
    let declaration = if include_declaration {
        "ex:alice a owl:NamedIndividual ."
    } else {
        ""
    };
    let turtle = format!(
        r#"
@prefix ex: <{EX}> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .

ex:Employee rdfs:subClassOf ex:Person .
ex:parent owl:inverseOf ex:child .
ex:alice a ex:Employee ; ex:parent ex:bob .
{declaration}
"#
    );
    FlureeBuilder::memory()
        .build_memory()
        .stage_owned(genesis(id))
        .upsert_turtle(&turtle)
        .execute()
        .await
        .expect("focused NamedIndividual fixture must load")
        .ledger
}

async fn direct_reason(ledger: &LedgerState) -> std::sync::Arc<ReasoningResult> {
    reason_owl2rl(
        GraphDbRef::new(&ledger.snapshot, 0, ledger.novelty.as_ref(), ledger.t()),
        &ReasoningOptions::with_budget(ReasoningBudget::unlimited()),
        &ReasoningCache::new(1),
    )
    .await
    .expect("pinned Fluree direct reasoner must accept the declaration")
}

fn overlay_iri_triples(ledger: &LedgerState, result: &ReasoningResult) -> BTreeSet<IriTriple> {
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

async fn authored_iri_triples(ledger: &LedgerState) -> BTreeSet<IriTriple> {
    GraphDbRef::new(&ledger.snapshot, 0, ledger.novelty.as_ref(), ledger.t())
        .range(IndexType::Spot, RangeTest::Eq, RangeMatch::default())
        .await
        .expect("focused premise scan")
        .into_iter()
        .filter_map(|flake| {
            if !flake.op {
                return None;
            }
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

fn direct_diagnostics(
    result: &ReasoningResult,
) -> (usize, usize, bool, Option<String>, BTreeMap<String, usize>) {
    (
        result.diagnostics.iterations,
        result.diagnostics.facts_derived,
        result.diagnostics.capped,
        result.diagnostics.capped_reason.clone(),
        result
            .diagnostics
            .rules_fired
            .iter()
            .map(|(rule, count)| (rule.clone(), *count))
            .collect(),
    )
}

fn quad(graph: &str, subject: &str, predicate: &str, object: &str) -> SourceQuad {
    SourceQuad {
        graph: graph.to_owned(),
        subject: RdfNodeId::Iri(subject.to_owned()),
        predicate: predicate.to_owned(),
        object: ExactTerm::Iri(object.to_owned()),
    }
}

fn production_manifest(include_declaration: bool) -> AuthorizedViewManifest {
    let schema = BTreeSet::from([
        quad(SCHEMA_GRAPH, SCHEMA_GRAPH, RDF_TYPE, OWL_ONTOLOGY),
        quad(
            SCHEMA_GRAPH,
            &format!("{EX}Employee"),
            RDFS_SUBCLASS,
            &format!("{EX}Person"),
        ),
        quad(
            SCHEMA_GRAPH,
            &format!("{EX}parent"),
            OWL_INVERSE_OF,
            &format!("{EX}child"),
        ),
    ]);
    let mut data = BTreeSet::from([
        quad(
            DATA_GRAPH,
            &format!("{EX}alice"),
            RDF_TYPE,
            &format!("{EX}Employee"),
        ),
        quad(
            DATA_GRAPH,
            &format!("{EX}alice"),
            &format!("{EX}parent"),
            &format!("{EX}bob"),
        ),
    ]);
    if include_declaration {
        data.insert(quad(
            DATA_GRAPH,
            &format!("{EX}alice"),
            RDF_TYPE,
            OWL_NAMED_INDIVIDUAL,
        ));
    }

    let capture = SemanticCaptureDescriptor {
        ledger: "ctxql/p5-6-named-individual-probe:main".into(),
        requested_as_of: "t:1".into(),
        t: 1,
        commit_cid: "bafy-p5-6-named-individual-probe".into(),
    };
    let profile = classify_ontology_bundle_v2(&schema, OntologyProfileLimits::default()).unwrap();
    let input = build_reasoner_input(&capture, &data, &profile.reasoner_projection.quads).unwrap();
    AuthorizedViewManifest::seal_profiled_v2(
        capture,
        ReasoningDescriptor {
            schema_source: SCHEMA_GRAPH.into(),
            follow_owl_imports: false,
            schema_graphs: BTreeSet::from([SCHEMA_GRAPH.into()]),
        },
        data,
        schema,
        input,
        STRUCTURAL_MAPPING_ALGORITHM.into(),
        profile.limits_identity.clone(),
        BTreeSet::new(),
        ContentHash::of_bytes(b"p5-6-named-individual-probe-config"),
        OntologyProfileDescriptor {
            identity: profile.identity.into(),
            full_bundle_root: profile.full_bundle_root,
            result_root: profile.result_root,
        },
        ContentHash::of_bytes(b"p5-6-named-individual-probe-policy"),
        "ctxql-p5-6-complete/v1",
    )
}

#[test]
fn profile_v2_remains_unchanged_and_rejects_named_individual_in_schema() {
    let schema = BTreeSet::from([
        quad(SCHEMA_GRAPH, SCHEMA_GRAPH, RDF_TYPE, OWL_ONTOLOGY),
        quad(
            SCHEMA_GRAPH,
            &format!("{EX}alice"),
            RDF_TYPE,
            OWL_NAMED_INDIVIDUAL,
        ),
    ]);
    let failure = analyze_ontology_bundle_v2(&schema, OntologyProfileLimits::default())
        .expect_err("profile v2 must remain unchanged during the probe");
    assert!(failure.issues.iter().any(|issue| {
        issue.class == OntologyIssueClass::Unsupported
            && issue.reason == "ontology_reserved_type_unsupported"
            && issue.graph.as_deref() == Some(SCHEMA_GRAPH)
            && issue.predicate.as_deref() == Some(RDF_TYPE)
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn named_individual_is_retained_but_inference_inert_direct_and_production() {
    let baseline_ledger =
        direct_ledger("ctxql/p5-6-named-individual-direct-base:main", false).await;
    let declared_ledger =
        direct_ledger("ctxql/p5-6-named-individual-direct-declared:main", true).await;
    let baseline_direct = direct_reason(&baseline_ledger).await;
    let declared_direct = direct_reason(&declared_ledger).await;

    let declaration = (
        format!("{EX}alice"),
        RDF_TYPE.to_owned(),
        OWL_NAMED_INDIVIDUAL.to_owned(),
    );
    assert!(!authored_iri_triples(&baseline_ledger)
        .await
        .contains(&declaration));
    assert!(authored_iri_triples(&declared_ledger)
        .await
        .contains(&declaration));

    let baseline_direct_facts = overlay_iri_triples(&baseline_ledger, &baseline_direct);
    let declared_direct_facts = overlay_iri_triples(&declared_ledger, &declared_direct);
    assert_eq!(baseline_direct_facts, declared_direct_facts);
    assert!(!declared_direct_facts.contains(&declaration));
    assert_eq!(
        direct_diagnostics(&baseline_direct),
        direct_diagnostics(&declared_direct)
    );
    assert!(declared_direct_facts.contains(&(
        format!("{EX}alice"),
        RDF_TYPE.to_owned(),
        format!("{EX}Person"),
    )));
    assert!(declared_direct_facts.contains(&(
        format!("{EX}bob"),
        format!("{EX}child"),
        format!("{EX}alice"),
    )));

    let baseline_manifest = support::seal_for_current_reasoner(&production_manifest(false));
    let declared_manifest = support::seal_for_current_reasoner(&production_manifest(true));
    let baseline_production =
        reason_authorized_manifest(&baseline_manifest, SandboxLimits::default())
            .await
            .unwrap();
    let declared_production =
        reason_authorized_manifest(&declared_manifest, SandboxLimits::default())
            .await
            .unwrap();

    assert_eq!(
        baseline_production.inferred_facts,
        declared_production.inferred_facts
    );
    assert_eq!(
        baseline_production.diagnostics,
        declared_production.diagnostics
    );
    assert!(declared_production.asserted_data_quads.contains(&quad(
        DATA_GRAPH,
        &format!("{EX}alice"),
        RDF_TYPE,
        OWL_NAMED_INDIVIDUAL,
    )));
    assert!(!declared_production.inferred_facts.contains(&PreparedFact {
        subject: format!("{EX}alice"),
        predicate: RDF_TYPE.to_owned(),
        object: ExactTerm::Iri(OWL_NAMED_INDIVIDUAL.to_owned()),
    }));
    assert_eq!(
        baseline_direct_facts,
        baseline_production.inferred_iri_triples
    );
    assert_eq!(
        declared_direct_facts,
        declared_production.inferred_iri_triples
    );
}
