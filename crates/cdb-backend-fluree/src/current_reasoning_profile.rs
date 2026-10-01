//! Bounded executable ontology profile certified for the linked Fluree 4.2.1 reasoner.
//!
//! The accepted construct surface is intentionally the already-audited v2
//! structural subset. This module gives a fresh backend-bound identity and
//! result commitment to executions revalidated against 4.2.1; it does not
//! relabel archival `603974f` certificates.

use crate::{
    authorized_view::{framed_root, quad_root, SourceQuad},
    ontology_profile_v2::{
        classify_ontology_bundle_v2, OntologyProfileLimits, OntologyProfileV2Result,
    },
};
use std::collections::BTreeSet;

pub const CURRENT_REASONING_PROFILE_ID: &str =
    "ctxql-ontology-profile/fluree-4.2.1-82dbcec3e435d6ed1d45bc0ed929432323b6b201/v1-supported-reasoning";

/// Classify the closed schema bundle with the bounded structural validator,
/// then mint a result commitment that explicitly names the current backend.
pub fn classify_current_reasoning_profile(
    bundle: &BTreeSet<SourceQuad>,
    limits: OntologyProfileLimits,
) -> Result<OntologyProfileV2Result, String> {
    let mut result = classify_ontology_bundle_v2(bundle, limits)?;
    let harmless_root = quad_root(&result.harmless);
    let count_commitment = result
        .construct_counts
        .iter()
        .map(|(name, count)| format!("{}:{name}:{count}", name.len()))
        .collect::<Vec<_>>()
        .join("\0");
    result.identity = CURRENT_REASONING_PROFILE_ID;
    result.result_root = framed_root(
        "ctxql-ontology-profile-result/current-4.2.1-supported-reasoning/v1",
        [
            ("profile", CURRENT_REASONING_PROFILE_ID),
            ("backend", crate::backend_identity::BACKEND_ID),
            ("full-bundle", result.full_bundle_root.as_str()),
            (
                "reasoner-projection",
                result.reasoner_projection.root.as_str(),
            ),
            ("harmless", harmless_root.as_str()),
            ("limits", result.limits_identity.as_str()),
            ("counts", count_commitment.as_str()),
        ],
    );
    Ok(result)
}
