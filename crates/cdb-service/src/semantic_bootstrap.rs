//! Configuration-bound fresh Semantic authority bootstrap.

use crate::config::{AcquisitionProtocol, InstanceConfig};
use cdb_backend_fluree::fresh_semantic::{
    bootstrap_fresh_semantic, FreshSemanticPlan, FreshSemanticReceipt,
};
use cdb_core::{id::Iri, Error, ErrorKind, Result};

const MODIFY: &str = "https://ns.flur.ee/db#modify";

#[derive(Debug, serde::Serialize)]
pub struct BootstrapReceipt {
    #[serde(flatten)]
    pub semantic: FreshSemanticReceipt,
    pub catalog_root: String,
    pub ontology_profile: String,
}

/// Bootstrap only the Semantic destination named by a validated instance file.
/// Control, projection, credentials, and source storage are not opened.
pub async fn bootstrap(config: InstanceConfig) -> Result<BootstrapReceipt> {
    config.validate_runtime()?;
    let acquisition = config
        .acquisition
        .as_ref()
        .ok_or_else(|| Error::invalid("Semantic bootstrap requires acquisition configuration"))?;
    if acquisition.protocol != AcquisitionProtocol::OntologyV2 {
        return Err(Error::invalid(
            "Semantic bootstrap requires ontology-v2 acquisition",
        ));
    }
    if acquisition.action != MODIFY {
        return Err(Error::invalid(
            "Semantic bootstrap acquisition action must be native modify",
        ));
    }
    let principal = Iri::new(&acquisition.principal)?;
    let claims_graph = Iri::new(&acquisition.claims_graph)?;
    let review_graph = Iri::new(
        acquisition
            .review_graph
            .as_deref()
            .ok_or_else(|| Error::invalid("Semantic bootstrap requires review graph"))?,
    )?;
    let semantic = config
        .semantic
        .as_ref()
        .ok_or_else(|| Error::invalid("Semantic bootstrap requires Semantic authority"))?;
    let infrastructure_graph = Iri::new(&semantic.graph)?;
    let (path, options) = config.semantic_binding()?;
    if options.backend.as_str() != cdb_core::recording_v5::BACKEND_ID {
        return Err(Error::invalid(
            "Semantic bootstrap requires the pinned native backend identity",
        ));
    }
    let path = path.to_path_buf();
    let semantic = bootstrap_fresh_semantic(
        &path,
        FreshSemanticPlan {
            options,
            principal,
            claims_graph,
            review_graph,
            infrastructure_graph,
        },
    )
    .await
    .map_err(|error| Error::new(ErrorKind::Backend, error.to_string()))?;
    let catalog = crate::acquisition::load_current_catalog(&config).await?;
    Ok(BootstrapReceipt {
        semantic,
        catalog_root: catalog.identity().catalog_root().as_str().into(),
        ontology_profile: catalog.identity().profile_identity().into(),
    })
}
