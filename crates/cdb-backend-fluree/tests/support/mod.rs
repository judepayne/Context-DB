use cdb_backend_fluree::{
    authorized_view::{build_reasoner_input, AuthorizedViewManifest, OntologyProfileDescriptor},
    current_reasoning_profile::classify_current_reasoning_profile,
    ontology_profile_v2::{OntologyProfileLimits, STRUCTURAL_MAPPING_ALGORITHM},
};

/// Reseal a freshly constructed test manifest for execution by the current
/// native reasoner. Archival manifests remain unchanged and unsupported.
pub fn seal_for_current_reasoner(manifest: &AuthorizedViewManifest) -> AuthorizedViewManifest {
    let profile = classify_current_reasoning_profile(
        &manifest.schema_quads,
        OntologyProfileLimits::default(),
    )
    .expect("test schema must satisfy the current native reasoning profile");
    let reasoner_input = build_reasoner_input(
        &manifest.capture,
        &manifest.data_quads,
        &profile.reasoner_projection.quads,
    )
    .expect("current-profile test input must be canonical");
    AuthorizedViewManifest::seal_profiled_v2(
        manifest.capture.clone(),
        manifest.reasoning.clone(),
        manifest.data_quads.clone(),
        manifest.schema_quads.clone(),
        reasoner_input,
        STRUCTURAL_MAPPING_ALGORITHM.into(),
        profile.limits_identity.clone(),
        manifest.visible_supports.clone(),
        manifest.historical_config_root.clone(),
        OntologyProfileDescriptor {
            identity: profile.identity.into(),
            full_bundle_root: profile.full_bundle_root,
            result_root: profile.result_root,
        },
        manifest.policy_dependency_root.clone(),
        &manifest.protected_completeness,
    )
}
