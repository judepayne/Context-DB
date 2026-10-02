//! Generic create-once Semantic authority bootstrap.

use crate::{
    semantic::{FlureeSemanticLedger, SemanticLedgerOptions},
    semantic_policy::{resolve_current_semantic_authority, SemanticPolicyMode},
};
use cdb_core::id::{ContentHash, Iri};
use fluree_db_api::FlureeBuilder;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

pub type BootstrapResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Debug)]
pub struct FreshSemanticPlan {
    pub options: SemanticLedgerOptions,
    pub principal: Iri,
    pub claims_graph: Iri,
    pub review_graph: Iri,
    pub infrastructure_graph: Iri,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FreshSemanticReceipt {
    pub schema: String,
    pub storage_path: String,
    pub ledger: String,
    pub t: i64,
    pub cid: String,
    pub principal: String,
    pub claims_graph: String,
    pub review_graph: String,
    pub infrastructure_graph: String,
    pub reasoning_mode: String,
    pub default_allow: bool,
}

fn validate_ledger_id(value: &str) -> BootstrapResult<()> {
    let (name, branch) = fluree_db_core::split_ledger_id(value)?;
    let safe = |part: &str, slash: bool| {
        !part.is_empty()
            && part.len() <= 256
            && !part
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
            && part.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') || (slash && c == '/')
            })
    };
    if !safe(&name, true) || !safe(&branch, false) || value.contains('@') {
        return Err("invalid Semantic ledger identifier".into());
    }
    Ok(())
}

fn validate(plan: &FreshSemanticPlan, output: &Path) -> BootstrapResult<()> {
    if !output.is_absolute() {
        return Err("Semantic bootstrap path must be absolute".into());
    }
    validate_ledger_id(plan.options.ledger.as_str())?;
    let mut roles = [
        plan.claims_graph.as_str(),
        plan.review_graph.as_str(),
        plan.infrastructure_graph.as_str(),
    ];
    roles.sort_unstable();
    if roles[0] == roles[1] || roles[1] == roles[2] {
        return Err("Semantic graph roles must be distinct".into());
    }
    let parent = output
        .parent()
        .ok_or("Semantic bootstrap destination has no parent")?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err("Semantic bootstrap parent must be an existing directory".into());
    }
    match fs::symlink_metadata(output) {
        Ok(_) => return Err("Semantic bootstrap destination already exists".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Create exactly one fresh file-backed Semantic ledger. This never opens,
/// resets, migrates, or removes an existing destination.
pub async fn bootstrap_fresh_semantic(
    output: &Path,
    plan: FreshSemanticPlan,
) -> BootstrapResult<FreshSemanticReceipt> {
    validate(&plan, output)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(output)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(output)?;

    let ledger_id = plan.options.ledger.as_str();
    let config_graph = fluree_db_core::graph_registry::config_graph_iri(ledger_id);
    let identity = ContentHash::of_bytes(
        format!(
            "{}\0{}\0{}\0{}",
            ledger_id,
            plan.principal.as_str(),
            plan.claims_graph.as_str(),
            plan.review_graph.as_str()
        )
        .as_bytes(),
    );
    let base = format!("urn:ctxql:semantic-bootstrap:{}", &identity.as_str()[7..]);
    let policy_graph = format!("{base}:policy");
    let turtle = format!(
        r#"@prefix f: <https://ns.flur.ee/db#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix ctxql: <https://ctxql.example/semantic-rdf/v1/> .
GRAPH <{config_graph}> {{
  <{base}:config> rdf:type f:LedgerConfig ;
    f:reasoningDefaults <{base}:reasoning> ;
    f:policyDefaults <{base}:policy-defaults> ;
    ctxql:governedDataGraph <{claims}> ;
    ctxql:claimGraph <{claims}> ;
    ctxql:reviewGraph <{review}> ;
    ctxql:infrastructureGraph <{infrastructure}> .
  <{base}:reasoning> f:reasoningModes f:none ;
    f:schemaSource <{base}:schema-ref> ; f:followOwlImports false .
  <{base}:schema-ref> rdf:type f:GraphRef ; f:graphSource <{base}:schema-source> .
  <{base}:schema-source> f:graphSelector <{infrastructure}> .
  <{base}:policy-defaults> f:defaultAllow false ; f:policySource <{base}:policy-ref> .
  <{base}:policy-ref> rdf:type f:GraphRef ; f:graphSource <{base}:policy-source> .
  <{base}:policy-source> f:graphSelector <{policy_graph}> .
}}
GRAPH <{policy_graph}> {{
  <{principal}> f:policyClass <{base}:OwnerPolicy> .
  <{base}:owner-view> rdf:type f:AccessPolicy, <{base}:OwnerPolicy> ;
    f:action f:view ; f:allow true .
  <{base}:owner-modify> rdf:type f:AccessPolicy, <{base}:OwnerPolicy> ;
    f:action f:modify ; f:allow true .
}}
GRAPH <{infrastructure}> {{ <{infrastructure}> rdf:type owl:Ontology . }}
GRAPH <{claims}> {{ <{claims}> rdf:type <http://www.w3.org/2004/03/trix/rdfg-1/Graph> . }}
GRAPH <{review}> {{ <{review}> rdf:type <http://www.w3.org/2004/03/trix/rdfg-1/Graph> . }}"#,
        claims = plan.claims_graph.as_str(),
        review = plan.review_graph.as_str(),
        infrastructure = plan.infrastructure_graph.as_str(),
        principal = plan.principal.as_str(),
    );

    let writer = FlureeBuilder::file(output.to_string_lossy().into_owned())
        .without_indexing()
        .build()?;
    let ledger = writer.create_ledger(ledger_id).await?;
    let committed = writer
        .stage_owned(ledger)
        .upsert_turtle(&turtle)
        .execute()
        .await?
        .ledger;
    let cid = committed
        .head_commit_id
        .as_ref()
        .ok_or("Semantic bootstrap commit has no CID")?
        .to_string();
    if committed.t() != 1 {
        return Err("Semantic bootstrap was not one transaction".into());
    }
    drop(writer);

    let reader = FlureeSemanticLedger::open_file(output, plan.options.clone()).await?;
    for action in ["https://ns.flur.ee/db#view", "https://ns.flur.ee/db#modify"] {
        let authority =
            resolve_current_semantic_authority(&reader, plan.principal.as_str(), action).await?;
        if authority.basis.mode != SemanticPolicyMode::Configured || authority.enforcer().is_none()
        {
            return Err("Semantic owner policy did not resolve".into());
        }
    }

    Ok(FreshSemanticReceipt {
        schema: "ctxql-fresh-semantic-bootstrap/v1".into(),
        storage_path: output.canonicalize()?.to_string_lossy().into_owned(),
        ledger: ledger_id.into(),
        t: 1,
        cid,
        principal: plan.principal.as_str().into(),
        claims_graph: plan.claims_graph.as_str().into(),
        review_graph: plan.review_graph.as_str().into(),
        infrastructure_graph: plan.infrastructure_graph.as_str().into(),
        reasoning_mode: "none".into(),
        default_allow: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        acquisition_catalog::CertifiedOntologyCatalog,
        semantic_preparation::{prepare_current_authorized_view, ExtractionLimits},
    };
    use cdb_core::id::{AuthorityId, BackendId, GraphId};
    use fluree_db_core::GraphDbRef;
    use fluree_db_query::{
        execute, ContextConfig, ExecutableQuery, Pattern, Query, QueryOutput, Ref, Term,
        TriplePattern, VarRegistry,
    };

    fn plan() -> FreshSemanticPlan {
        FreshSemanticPlan {
            options: SemanticLedgerOptions {
                backend: BackendId::new(cdb_core::recording_v5::BACKEND_ID).unwrap(),
                authority: AuthorityId::new("urn:test:authority:semantic").unwrap(),
                ledger: GraphId::new("generic-semantic:main").unwrap(),
            },
            principal: Iri::new("did:example:generic-owner").unwrap(),
            claims_graph: Iri::new("https://example.test/graphs/claims").unwrap(),
            review_graph: Iri::new("https://example.test/graphs/review").unwrap(),
            infrastructure_graph: Iri::new("https://example.test/graphs/schema").unwrap(),
        }
    }

    #[tokio::test]
    async fn fresh_policy_allows_owner_and_rejects_unknown_principal() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("semantic");
        let receipt = bootstrap_fresh_semantic(&output, plan()).await.unwrap();
        assert_eq!(receipt.t, 1);
        assert!(!receipt.default_allow);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }

        let reader = FlureeSemanticLedger::open_file(&output, plan().options)
            .await
            .unwrap();
        async fn visible_schema_rows(reader: &FlureeSemanticLedger, principal: &str) -> usize {
            let authority =
                resolve_current_semantic_authority(reader, principal, "https://ns.flur.ee/db#view")
                    .await
                    .unwrap();
            let state = reader.current_state().await.unwrap();
            let graph = state
                .snapshot
                .graph_registry
                .graph_id_for_iri("https://example.test/graphs/schema")
                .unwrap();
            let mut vars = VarRegistry::new();
            let s = vars.get_or_insert("?s");
            let p = vars.get_or_insert("?p");
            let o = vars.get_or_insert("?o");
            let mut query = Query::new(Default::default());
            query.output = QueryOutput::select_all(vec![s, p, o]);
            query.patterns = vec![Pattern::Triple(TriplePattern::new(
                Ref::Var(s),
                Ref::Var(p),
                Term::Var(o),
            ))];
            execute(
                GraphDbRef::new(&state.snapshot, graph, state.novelty.as_ref(), state.t()).eager(),
                &vars,
                &ExecutableQuery::simple(query),
                ContextConfig {
                    policy_enforcer: authority.enforcer(),
                    ..ContextConfig::default()
                },
            )
            .await
            .unwrap()
            .iter()
            .map(|batch| batch.len())
            .sum()
        }

        assert_eq!(
            visible_schema_rows(&reader, "did:example:generic-owner").await,
            1
        );
        assert_eq!(visible_schema_rows(&reader, "did:example:unknown").await, 0);

        let prepared = prepare_current_authorized_view(
            &reader,
            "did:example:generic-owner",
            "https://ns.flur.ee/db#modify",
            ExtractionLimits::default(),
        )
        .await
        .unwrap();
        assert!(prepared.authorized_claims.is_empty());
        assert_eq!(prepared.manifest.data_quads.len(), 1);
        let registration = prepared.manifest.data_quads.iter().next().unwrap();
        assert_eq!(registration.graph, plan().claims_graph.as_str());
        assert_eq!(
            registration.subject.as_iri(),
            Some(plan().claims_graph.as_str())
        );
        assert_eq!(
            registration.predicate,
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        );
        assert_eq!(
            registration.object.as_iri(),
            Some("http://www.w3.org/2004/03/trix/rdfg-1/Graph")
        );
        assert_eq!(prepared.manifest.schema_quads.len(), 1);
        let catalog = CertifiedOntologyCatalog::from_prepared(&prepared, reader.options()).unwrap();
        assert_eq!(
            catalog.identity().profile_identity(),
            cdb_core::recording_v5::CURRENT_ACQUISITION_PROFILE_ID
        );
    }

    #[tokio::test]
    async fn existing_destination_is_never_clobbered() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("semantic");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("marker"), b"keep").unwrap();
        assert!(bootstrap_fresh_semantic(&output, plan()).await.is_err());
        assert_eq!(fs::read(output.join("marker")).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_destination_is_refused() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        let output = root.path().join("semantic");
        symlink(&target, &output).unwrap();
        assert!(bootstrap_fresh_semantic(&output, plan()).await.is_err());
        assert!(fs::read_dir(target).unwrap().next().is_none());
    }
}
