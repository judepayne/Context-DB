//! Capture-bound, policy-filtered lookup for established Semantic entities.
//!
//! Labels are discovery text only.  Resolution requires an identifying value
//! read from the authorized Semantic view; a label match can never preserve a
//! proposed global IRI.

use cdb_backend_fluree::{
    authorized_view::{ExactTerm, SourceQuad},
    semantic::FlureeSemanticLedger,
    semantic_policy::verify_semantic_authority_current,
    semantic_preparation::PreparedAuthorizedView,
};
use cdb_core::id::ContentHash;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
pub const RDFS_LABEL: &str = "http://www.w3.org/2000/01/rdf-schema#label";
pub const SKOS_PREF_LABEL: &str = "http://www.w3.org/2004/02/skos/core#prefLabel";
pub const SKOS_ALT_LABEL: &str = "http://www.w3.org/2004/02/skos/core#altLabel";
const MAX_APPROVED_ENTITIES: usize = 4096;
const MAX_RESULTS: usize = 128;

/// Explicit host-side eligibility filters. Empty graph or identifying-predicate
/// sets are rejected rather than interpreted as wildcards. An empty class set
/// means that no additional class restriction was configured.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityEligibility {
    pub allowed_graphs: BTreeSet<String>,
    pub allowed_classes: BTreeSet<String>,
    pub identifying_predicates: BTreeSet<String>,
    pub label_predicates: BTreeSet<String>,
}

impl EntityEligibility {
    /// Small POC profile using the conventional RDF label predicates. The
    /// caller still has to provide explicit graph, class, and identifier policy.
    pub fn poc(
        allowed_graphs: BTreeSet<String>,
        allowed_classes: BTreeSet<String>,
        identifying_predicates: BTreeSet<String>,
    ) -> Self {
        Self {
            allowed_graphs,
            allowed_classes,
            identifying_predicates,
            label_predicates: [RDFS_LABEL, SKOS_PREF_LABEL, SKOS_ALT_LABEL]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GazetteerIdentifier {
    pub predicate: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GazetteerEntity {
    pub iri: String,
    pub labels: Vec<String>,
    pub classes: Vec<String>,
    pub identifiers: Vec<GazetteerIdentifier>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KnownMention {
    /// Absolute UTF-8 byte offsets in the supplied passage.
    pub start: usize,
    pub end: usize,
    pub text: String,
    /// Collision sets are retained; ordering is canonical.
    pub candidate_iris: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentifierProbe {
    pub predicate: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum KnownIriResolution {
    Resolved { iri: String },
    NotApproved,
    IdentifierRequired,
    IdentifierMismatch,
    Ambiguous { candidate_iris: Vec<String> },
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntityLookupRequest {
    Search { text: String, limit: usize },
    Describe { iri: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EntityLookupResponse {
    Results { entities: Vec<GazetteerEntity> },
    Found { entity: GazetteerEntity },
    NotFound,
    InvalidRequest,
}

/// Immutable lookup built only from a prepared, authorized Semantic capture.
#[derive(Clone, Debug)]
pub struct EntityGazetteer {
    entities: BTreeMap<String, GazetteerEntity>,
    aliases: BTreeMap<String, BTreeSet<String>>,
    identifier_index: BTreeMap<(String, String), BTreeSet<String>>,
    approved: BTreeSet<String>,
    capture_ledger: String,
    capture_t: i64,
    capture_cid: String,
    policy_basis: cdb_backend_fluree::semantic_policy::SemanticPolicyBasis,
    commitment: ContentHash,
    dependencies: BTreeSet<String>,
    context_protectable: bool,
    class_supports: BTreeMap<String, Vec<cdb_core::classification::ClassificationRef>>,
}

impl EntityGazetteer {
    /// Intersect the explicit approval list with the pinned, policy-authorized
    /// Semantic preparation and explicit eligibility filters.
    pub fn from_prepared(
        approved_entity_iris: &[String],
        prepared: &PreparedAuthorizedView,
        eligibility: &EntityEligibility,
    ) -> Result<Self, String> {
        validate_filters(prepared, eligibility)?;
        let approved = validate_approvals(approved_entity_iris)?;
        let mut host = Self::build(
            approved,
            &prepared.manifest.data_quads,
            eligibility,
            prepared.manifest.capture.ledger.clone(),
            prepared.manifest.capture.t,
            prepared.manifest.capture.commit_cid.clone(),
            prepared.policy_basis.clone(),
            prepared.manifest.data_root.as_str(),
            prepared
                .manifest
                .visible_supports
                .iter()
                .map(String::as_str),
            prepared.graph_role_map_root.as_str(),
        )?;
        let mut covered = BTreeSet::new();
        for record in &prepared.authorized_claims {
            let Some(claim) = record.claim() else {
                continue;
            };
            let candidate = claim.candidate();
            let Some(entity) = host.entities.get(candidate.subject().as_str()) else {
                continue;
            };
            let predicate = candidate.relation().as_str();
            let is_retained_fact = if predicate == RDF_TYPE {
                matches!(candidate.object(), cdb_core::claim::ClaimObject::Entity(class) if entity.classes.iter().any(|iri| iri == class.as_str()))
            } else if eligibility.label_predicates.contains(predicate) {
                matches!(candidate.object(), cdb_core::claim::ClaimObject::Literal(value) if value.value().as_str().is_ok_and(|lexical| entity.labels.iter().any(|label| label == lexical)))
            } else if eligibility.identifying_predicates.contains(predicate) {
                entity.identifiers.iter().any(|identifier| {
                    identifier.predicate == predicate
                        && match candidate.object() {
                            cdb_core::claim::ClaimObject::Entity(value) => {
                                identifier.value == value.as_str()
                            }
                            cdb_core::claim::ClaimObject::Literal(value) => value
                                .value()
                                .as_str()
                                .is_ok_and(|lexical| identifier.value == lexical),
                        }
                })
            } else {
                false
            };
            if !is_retained_fact {
                continue;
            }
            host.dependencies.insert(claim.id().as_str().to_owned());
            let value = match candidate.object() {
                cdb_core::claim::ClaimObject::Entity(value) => value.as_str(),
                cdb_core::claim::ClaimObject::Literal(value) => {
                    value.value().as_str().map_err(|e| e.to_string())?
                }
            };
            covered.insert((
                entity.iri.clone(),
                if eligibility.label_predicates.contains(predicate) {
                    "label".to_owned()
                } else {
                    predicate.to_owned()
                },
                value.to_owned(),
            ));
            if predicate == RDF_TYPE {
                let cdb_core::claim::ClaimObject::Entity(class) = candidate.object() else {
                    unreachable!()
                };
                host.class_supports
                    .entry(entity.iri.clone())
                    .or_default()
                    .push(cdb_core::classification::ClassificationRef::new(
                        cdb_core::id::Iri::new(class.as_str())
                            .map_err(|error| error.to_string())?,
                        cdb_core::classification::ClassificationOrigin::Established,
                        cdb_core::id::ResourceId::new(claim.id().as_str())
                            .map_err(|error| error.to_string())?,
                    ));
            }
        }
        host.context_protectable = host.entities.values().all(|entity| {
            entity.classes.iter().all(|value| {
                covered.contains(&(entity.iri.clone(), RDF_TYPE.to_owned(), value.clone()))
            }) && entity.labels.iter().all(|value| {
                covered.contains(&(entity.iri.clone(), "label".to_owned(), value.clone()))
            }) && entity.identifiers.iter().all(|identifier| {
                covered.contains(&(
                    entity.iri.clone(),
                    identifier.predicate.clone(),
                    identifier.value.clone(),
                ))
            })
        });
        Ok(host)
    }

    pub(crate) fn classification_refs(
        &self,
        iri: &str,
    ) -> &[cdb_core::classification::ClassificationRef] {
        self.class_supports
            .get(iri)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    #[allow(clippy::too_many_arguments)]
    fn build<'a>(
        approved: BTreeSet<String>,
        quads: &BTreeSet<SourceQuad>,
        eligibility: &EntityEligibility,
        capture_ledger: String,
        capture_t: i64,
        capture_cid: String,
        policy_basis: cdb_backend_fluree::semantic_policy::SemanticPolicyBasis,
        data_root: &str,
        visible_supports: impl Iterator<Item = &'a str>,
        graph_role_map_root: &str,
    ) -> Result<Self, String> {
        let mut facts = BTreeMap::<String, Vec<&SourceQuad>>::new();
        for quad in quads
            .iter()
            .filter(|quad| eligibility.allowed_graphs.contains(&quad.graph))
        {
            if let Some(subject) = quad.subject_iri().filter(|iri| approved.contains(*iri)) {
                facts.entry(subject.to_owned()).or_default().push(quad);
            }
        }

        let mut entities = BTreeMap::new();
        let mut aliases = BTreeMap::<String, BTreeSet<String>>::new();
        let mut identifier_index = BTreeMap::<(String, String), BTreeSet<String>>::new();
        for iri in &approved {
            let Some(entity_facts) = facts.get(iri) else {
                continue;
            };
            let classes = literal_or_iri_values(entity_facts, RDF_TYPE, true);
            if !eligibility.allowed_classes.is_empty()
                && classes
                    .iter()
                    .all(|class| !eligibility.allowed_classes.contains(class))
            {
                continue;
            }
            let mut labels = BTreeSet::new();
            let mut identifiers = BTreeSet::new();
            for quad in entity_facts {
                if eligibility.label_predicates.contains(&quad.predicate) {
                    if let Some(value) = literal_value(&quad.object) {
                        labels.insert(value.to_owned());
                    }
                }
                if eligibility.identifying_predicates.contains(&quad.predicate) {
                    if let Some(value) = term_value(&quad.object) {
                        identifiers.insert((quad.predicate.clone(), value.to_owned()));
                    }
                }
            }
            // Presence and labels alone are insufficient eligibility for an
            // established identity in this profile.
            if identifiers.is_empty() {
                continue;
            }
            let entity = GazetteerEntity {
                iri: iri.clone(),
                labels: labels.into_iter().collect(),
                classes,
                identifiers: identifiers
                    .iter()
                    .map(|(predicate, value)| GazetteerIdentifier {
                        predicate: predicate.clone(),
                        value: value.clone(),
                    })
                    .collect(),
            };
            for label in &entity.labels {
                aliases
                    .entry(label.clone())
                    .or_default()
                    .insert(iri.clone());
            }
            for (predicate, value) in identifiers {
                identifier_index
                    .entry((predicate, value))
                    .or_default()
                    .insert(iri.clone());
            }
            entities.insert(iri.clone(), entity);
        }

        let supports = visible_supports.collect::<Vec<_>>();
        let commitment = gazetteer_commitment(
            &approved,
            eligibility,
            &capture_ledger,
            capture_t,
            &capture_cid,
            policy_basis.dependency_root.as_str(),
            &policy_basis.principal,
            &policy_basis.action,
            &policy_basis.source_observation,
            data_root,
            &supports,
            graph_role_map_root,
            entities.values(),
        );
        Ok(Self {
            entities,
            aliases,
            identifier_index,
            approved,
            capture_ledger,
            capture_t,
            capture_cid,
            policy_basis,
            commitment,
            dependencies: BTreeSet::new(),
            context_protectable: false,
            class_supports: BTreeMap::new(),
        })
    }

    /// Retain the actual identity context, not a recipe for substituting a
    /// newer gazetteer during replay. Outer graph-context roots protect bytes.
    pub(crate) fn replay_snapshot(&self) -> Result<String, String> {
        if !self.context_protectable {
            return Err("gazetteer context lacks exact claim support".into());
        }
        let supports = self
            .class_supports
            .iter()
            .map(|(iri, refs)| {
                let refs = refs
                    .iter()
                    .map(|r| {
                        serde_json::from_slice::<serde_json::Value>(
                            &r.projection()
                                .canonical_bytes(cdb_core::Limits::default())
                                .map_err(|e| e.to_string())?,
                        )
                        .map_err(|e| e.to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((iri.clone(), refs))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        serde_json::to_string(&serde_json::json!({
            "schema":"ctxql-retained-gazetteer/v1", "entities":self.entities,
            "approved":self.entities.keys().collect::<Vec<_>>(),
            "approval_root":ContentHash::of_bytes(&serde_json::to_vec(&self.approved).map_err(|e| e.to_string())?).as_str(),
            "class_supports":supports,
            "commitment":self.commitment.as_str(), "dependencies":self.dependencies,
        }))
        .map_err(|e| e.to_string())
    }

    /// Restore retained context only after checking every frozen fact/support
    /// against a freshly authorized view. Its current head becomes the release
    /// fence for this replay; live gazetteer head-freshness is unchanged.
    pub(crate) fn restore_replay_snapshot(&mut self, text: &str) -> Result<(), String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Snapshot {
            schema: String,
            entities: BTreeMap<String, GazetteerEntity>,
            approved: BTreeSet<String>,
            approval_root: String,
            class_supports: BTreeMap<String, Vec<serde_json::Value>>,
            commitment: String,
            dependencies: BTreeSet<String>,
        }
        cdb_core::CanonicalValue::parse(text.as_bytes(), cdb_core::Limits::default())
            .map_err(|e| e.to_string())?;
        let snapshot: Snapshot = serde_json::from_str(text).map_err(|e| e.to_string())?;
        if !self.context_protectable
            || snapshot.schema != "ctxql-retained-gazetteer/v1"
            || snapshot.approval_root
                != ContentHash::of_bytes(
                    &serde_json::to_vec(&self.approved).map_err(|e| e.to_string())?,
                )
                .as_str()
            || snapshot.approved != snapshot.entities.keys().cloned().collect()
            || !snapshot.approved.is_subset(&self.approved)
            || !snapshot.dependencies.is_subset(&self.dependencies)
        {
            return Err("captured gazetteer is no longer authorized".into());
        }
        for (iri, entity) in &snapshot.entities {
            let current = self
                .entities
                .get(iri)
                .ok_or("captured identity unavailable")?;
            if entity.iri != *iri
                || !entity.labels.iter().all(|v| current.labels.contains(v))
                || !entity.classes.iter().all(|v| current.classes.contains(v))
                || !entity
                    .identifiers
                    .iter()
                    .all(|v| current.identifiers.contains(v))
            {
                return Err("captured identity facts unavailable".into());
            }
            for identifier in &entity.identifiers {
                let key = (identifier.predicate.clone(), identifier.value.clone());
                if self
                    .identifier_index
                    .get(&key)
                    .is_none_or(|values| values.len() != 1 || !values.contains(iri))
                {
                    return Err("captured identity is now ambiguous".into());
                }
            }
        }
        let mut supports = BTreeMap::new();
        for (iri, refs) in snapshot.class_supports {
            let refs = refs
                .into_iter()
                .map(|value| {
                    let bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
                    let value =
                        cdb_core::CanonicalValue::parse(&bytes, cdb_core::Limits::default())
                            .map_err(|e| e.to_string())?;
                    self.classification_refs(&iri)
                        .iter()
                        .find(|reference| reference.projection() == value)
                        .cloned()
                        .ok_or_else(|| "captured classification unavailable".to_owned())
                })
                .collect::<Result<Vec<_>, String>>()?;
            supports.insert(iri, refs);
        }
        self.entities = snapshot.entities;
        self.dependencies = snapshot.dependencies;
        self.class_supports = supports;
        self.commitment = ContentHash::parse(snapshot.commitment).map_err(|e| e.to_string())?;
        self.aliases.clear();
        self.identifier_index.clear();
        for (iri, entity) in &self.entities {
            for label in &entity.labels {
                self.aliases
                    .entry(label.clone())
                    .or_default()
                    .insert(iri.clone());
            }
            for identifier in &entity.identifiers {
                self.identifier_index
                    .entry((identifier.predicate.clone(), identifier.value.clone()))
                    .or_default()
                    .insert(iri.clone());
            }
        }
        Ok(())
    }

    pub fn commitment(&self) -> &ContentHash {
        &self.commitment
    }

    /// Exact authorized claims whose facts were exposed through the initial
    /// gazetteer. These remain protected even when no graph query returns them.
    pub(crate) fn dependencies(&self) -> &BTreeSet<String> {
        &self.dependencies
    }

    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entities.len()
    }

    pub fn describe(&self, iri: &str) -> Option<&GazetteerEntity> {
        self.entities.get(iri)
    }

    pub fn search(&self, text: &str, limit: usize) -> Vec<GazetteerEntity> {
        if text.is_empty() || limit == 0 || limit > MAX_RESULTS {
            return Vec::new();
        }
        let needle = normalize(text);
        self.entities
            .values()
            .filter(|entity| {
                entity.iri.to_lowercase().contains(&needle)
                    || entity
                        .labels
                        .iter()
                        .any(|label| normalize(label).contains(&needle))
                    || entity
                        .identifiers
                        .iter()
                        .any(|id| normalize(&id.value).contains(&needle))
            })
            .take(limit)
            .cloned()
            .collect()
    }

    /// Render exact label occurrences. Offsets are byte coordinates even when
    /// preceding text or the label itself is non-ASCII.
    pub fn known_mentions(&self, passage: &str) -> Vec<KnownMention> {
        self.known_mentions_at(passage, 0)
    }

    /// Render passage matches in absolute document UTF-8 coordinates.
    pub fn known_mentions_at(&self, passage: &str, document_offset: usize) -> Vec<KnownMention> {
        let mut mentions = Vec::new();
        for (alias, iris) in &self.aliases {
            if alias.is_empty() {
                continue;
            }
            // Exact source spelling keeps offsets valid for every UTF-8 label;
            // case-insensitive discovery remains available through `search`.
            for (start, _) in passage.match_indices(alias) {
                let end = start + alias.len();
                mentions.push(KnownMention {
                    start: document_offset.saturating_add(start),
                    end: document_offset.saturating_add(end),
                    text: passage[start..end].to_owned(),
                    candidate_iris: iris.iter().cloned().collect(),
                });
            }
        }
        mentions.sort_by(|left, right| {
            (left.start, left.end, &left.candidate_iris).cmp(&(
                right.start,
                right.end,
                &right.candidate_iris,
            ))
        });
        mentions
    }

    pub fn render_known_mentions(&self, passage: &str) -> Result<String, String> {
        self.render_known_mentions_at(passage, 0)
    }

    pub fn render_known_mentions_at(
        &self,
        passage: &str,
        document_offset: usize,
    ) -> Result<String, String> {
        serde_json::to_string(&self.known_mentions_at(passage, document_offset))
            .map_err(|_| "entity_lookup_render_failed".to_owned())
    }

    /// Guarded model-context release. Prefer this over the pure renderer at a
    /// disclosure boundary.
    pub async fn release_known_mentions(
        &self,
        ledger: &FlureeSemanticLedger,
        passage: &str,
        document_offset: usize,
    ) -> Result<String, String> {
        self.recheck_release(ledger).await?;
        self.render_known_mentions_at(passage, document_offset)
    }

    /// Resolve a model-proposed established IRI only when authorized source
    /// identifiers uniquely select it. Labels are deliberately not accepted.
    pub fn resolve_known_iri(
        &self,
        proposed_iri: &str,
        identifiers: &[IdentifierProbe],
    ) -> KnownIriResolution {
        if !self.approved.contains(proposed_iri) || !self.entities.contains_key(proposed_iri) {
            return KnownIriResolution::NotApproved;
        }
        if identifiers.is_empty() {
            return KnownIriResolution::IdentifierRequired;
        }
        let mut matches: Option<BTreeSet<String>> = None;
        for identifier in identifiers {
            let matching = self
                .identifier_index
                .get(&(identifier.predicate.clone(), identifier.value.clone()))
                .cloned()
                .unwrap_or_default();
            matches = Some(match matches {
                None => matching,
                Some(current) => current.intersection(&matching).cloned().collect(),
            });
        }
        let matches = matches.unwrap_or_default();
        if matches.is_empty() || !matches.contains(proposed_iri) {
            return KnownIriResolution::IdentifierMismatch;
        }
        if matches.len() != 1 {
            return KnownIriResolution::Ambiguous {
                candidate_iris: matches.into_iter().collect(),
            };
        }
        KnownIriResolution::Resolved {
            iri: proposed_iri.to_owned(),
        }
    }

    /// Closed, bounded `ctxql_entities` request handler over this exact capture.
    pub fn ctxql_entities(&self, request: EntityLookupRequest) -> EntityLookupResponse {
        match request {
            EntityLookupRequest::Search { text, limit }
                if !text.is_empty() && (1..=MAX_RESULTS).contains(&limit) =>
            {
                EntityLookupResponse::Results {
                    entities: self.search(&text, limit),
                }
            }
            EntityLookupRequest::Describe { iri } if !iri.is_empty() => self
                .describe(&iri)
                .cloned()
                .map(|entity| EntityLookupResponse::Found { entity })
                .unwrap_or(EntityLookupResponse::NotFound),
            _ => EntityLookupResponse::InvalidRequest,
        }
    }

    /// Guarded tool response release over the same pinned capture.
    pub async fn release_ctxql_entities(
        &self,
        ledger: &FlureeSemanticLedger,
        request: EntityLookupRequest,
    ) -> Result<EntityLookupResponse, String> {
        self.recheck_release(ledger).await?;
        Ok(self.ctxql_entities(request))
    }

    /// Final release guard. It repeats policy resolution and requires the
    /// read-only ledger still to be at the exact capture used to build this
    /// object; callers must rebuild after any head or policy change.
    pub async fn recheck_release(&self, ledger: &FlureeSemanticLedger) -> Result<(), String> {
        verify_semantic_authority_current(ledger, &self.policy_basis).await?;
        let capture = ledger
            .capture_current(None)
            .await
            .map_err(|_| "entity_source_unavailable".to_owned())?;
        if ledger.options().ledger.as_str() != self.capture_ledger
            || i64::try_from(capture.t()).ok() != Some(self.capture_t)
            || capture.commit_cid().as_str() != self.capture_cid
        {
            return Err("entity_source_changed".to_owned());
        }
        verify_semantic_authority_current(ledger, &self.policy_basis).await
    }
}

fn validate_filters(
    prepared: &PreparedAuthorizedView,
    eligibility: &EntityEligibility,
) -> Result<(), String> {
    if eligibility.allowed_graphs.is_empty()
        || eligibility.identifying_predicates.is_empty()
        || eligibility.label_predicates.is_empty()
        || !eligibility
            .allowed_graphs
            .is_subset(&prepared.governed_data_graphs)
        || !eligibility
            .allowed_graphs
            .is_disjoint(&prepared.review_graphs)
    {
        return Err("entity_eligibility_invalid".to_owned());
    }
    Ok(())
}

fn validate_approvals(values: &[String]) -> Result<BTreeSet<String>, String> {
    if values.len() > MAX_APPROVED_ENTITIES
        || values.windows(2).any(|pair| pair[0] >= pair[1])
        || values
            .iter()
            .any(|value| cdb_core::id::Iri::new(value).is_err())
    {
        return Err("approved_entity_iris_invalid".to_owned());
    }
    Ok(values.iter().cloned().collect())
}

fn literal_value(term: &ExactTerm) -> Option<&str> {
    match term {
        ExactTerm::Literal { lexical, .. } => Some(lexical),
        ExactTerm::Iri(_) | ExactTerm::ScopedBlankNode(_) => None,
    }
}

fn term_value(term: &ExactTerm) -> Option<&str> {
    match term {
        ExactTerm::Iri(value) | ExactTerm::Literal { lexical: value, .. } => Some(value),
        ExactTerm::ScopedBlankNode(_) => None,
    }
}

fn literal_or_iri_values(quads: &[&SourceQuad], predicate: &str, iri_only: bool) -> Vec<String> {
    quads
        .iter()
        .filter(|quad| quad.predicate == predicate)
        .filter_map(|quad| {
            if iri_only {
                quad.object.as_iri()
            } else {
                term_value(&quad.object)
            }
        })
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalize(value: &str) -> String {
    value.to_lowercase()
}

fn frame(output: &mut String, name: &str, value: &str) {
    output.push_str(&name.len().to_string());
    output.push(':');
    output.push_str(name);
    output.push_str(&value.len().to_string());
    output.push(':');
    output.push_str(value);
}

#[allow(clippy::too_many_arguments)]
fn gazetteer_commitment<'a>(
    approved: &BTreeSet<String>,
    eligibility: &EntityEligibility,
    ledger: &str,
    t: i64,
    cid: &str,
    policy_root: &str,
    policy_principal: &str,
    policy_action: &str,
    policy_observation: &str,
    data_root: &str,
    supports: &[&str],
    graph_role_map_root: &str,
    entities: impl Iterator<Item = &'a GazetteerEntity>,
) -> ContentHash {
    let mut bytes = "ctxql-entity-gazetteer/v1".to_owned();
    for (name, value) in [
        ("ledger", ledger),
        ("t", &t.to_string()),
        ("cid", cid),
        ("policy", policy_root),
        ("policy-principal", policy_principal),
        ("policy-action", policy_action),
        ("policy-observation", policy_observation),
        ("data", data_root),
        ("graph-roles", graph_role_map_root),
    ] {
        frame(&mut bytes, name, value);
    }
    for value in approved {
        frame(&mut bytes, "approved", value);
    }
    for value in &eligibility.allowed_graphs {
        frame(&mut bytes, "graph", value);
    }
    for value in &eligibility.allowed_classes {
        frame(&mut bytes, "class", value);
    }
    for value in &eligibility.identifying_predicates {
        frame(&mut bytes, "identifier-predicate", value);
    }
    for value in &eligibility.label_predicates {
        frame(&mut bytes, "label-predicate", value);
    }
    for value in supports {
        frame(&mut bytes, "support", value);
    }
    for entity in entities {
        frame(&mut bytes, "entity", &entity.iri);
        for label in &entity.labels {
            frame(&mut bytes, "label", label);
        }
        for class in &entity.classes {
            frame(&mut bytes, "type", class);
        }
        for id in &entity.identifiers {
            frame(&mut bytes, &id.predicate, &id.value);
        }
    }
    ContentHash::of_bytes(bytes.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdb_backend_fluree::{
        authorized_view::RdfNodeId,
        semantic_policy::{SemanticPolicyBasis, SemanticPolicyMode},
    };

    const GRAPH: &str = "urn:test:business";
    const REVIEW: &str = "urn:test:review";
    const CLASS: &str = "urn:test:LegalEntity";
    const ID: &str = "urn:test:registration";
    const ALICE_A: &str = "urn:test:alice-a";
    const ALICE_B: &str = "urn:test:alice-b";
    const HIDDEN: &str = "urn:test:hidden";
    const INELIGIBLE: &str = "urn:test:ineligible";
    const REVIEW_ENTITY: &str = "urn:test:review-name";

    fn literal(value: &str) -> ExactTerm {
        ExactTerm::Literal {
            lexical: value.to_owned(),
            datatype: "http://www.w3.org/2001/XMLSchema#string".to_owned(),
            language: None,
        }
    }

    fn quad(graph: &str, subject: &str, predicate: &str, object: ExactTerm) -> SourceQuad {
        SourceQuad {
            graph: graph.to_owned(),
            subject: RdfNodeId::Iri(subject.to_owned()),
            predicate: predicate.to_owned(),
            object,
        }
    }

    fn source(include_hidden: bool) -> BTreeSet<SourceQuad> {
        let mut quads = BTreeSet::new();
        for (iri, registration) in [(ALICE_A, "A-1"), (ALICE_B, "B-2")] {
            quads.insert(quad(GRAPH, iri, RDFS_LABEL, literal("Alice Holdings")));
            quads.insert(quad(GRAPH, iri, ID, literal(registration)));
            quads.insert(quad(GRAPH, iri, RDF_TYPE, ExactTerm::Iri(CLASS.into())));
        }
        quads.insert(quad(
            GRAPH,
            INELIGIBLE,
            RDFS_LABEL,
            literal("Wrong Class Corp"),
        ));
        quads.insert(quad(GRAPH, INELIGIBLE, ID, literal("WRONG")));
        quads.insert(quad(
            GRAPH,
            INELIGIBLE,
            RDF_TYPE,
            ExactTerm::Iri("urn:test:OtherClass".into()),
        ));
        // Review records can look entity-like but are never eligible.
        quads.insert(quad(
            REVIEW,
            REVIEW_ENTITY,
            RDFS_LABEL,
            literal("Alice Holdings"),
        ));
        quads.insert(quad(REVIEW, REVIEW_ENTITY, ID, literal("R-9")));
        if include_hidden {
            quads.insert(quad(GRAPH, HIDDEN, RDFS_LABEL, literal("Secret Corp")));
            quads.insert(quad(GRAPH, HIDDEN, ID, literal("SECRET")));
            quads.insert(quad(GRAPH, HIDDEN, RDF_TYPE, ExactTerm::Iri(CLASS.into())));
        }
        quads
    }

    fn eligibility() -> EntityEligibility {
        EntityEligibility::poc(
            [GRAPH.to_owned()].into_iter().collect(),
            [CLASS.to_owned()].into_iter().collect(),
            [ID.to_owned()].into_iter().collect(),
        )
    }

    fn gazetteer(approved: &[&str], include_hidden: bool) -> EntityGazetteer {
        let approved = approved.iter().map(|value| (*value).to_owned()).collect();
        EntityGazetteer::build(
            approved,
            &source(include_hidden),
            &eligibility(),
            "urn:test:ledger".into(),
            7,
            "bafy-test".into(),
            SemanticPolicyBasis {
                mode: SemanticPolicyMode::Configured,
                dependency_root: ContentHash::of_bytes(b"policy"),
                principal: "tester".into(),
                action: "urn:test:lookup".into(),
                source_observation: "head".into(),
            },
            ContentHash::of_bytes(b"data").as_str(),
            ["urn:test:support"].into_iter(),
            ContentHash::of_bytes(b"roles").as_str(),
        )
        .unwrap()
    }

    #[test]
    fn replay_retains_original_identity_context_under_fresh_exact_authority() {
        let mut original = gazetteer(&[ALICE_A], false);
        assert!(
            original.replay_snapshot().is_err(),
            "raw facts without exact claim supports must remain withheld"
        );
        let mut restricted = gazetteer(&[ALICE_A, HIDDEN], false);
        restricted.context_protectable = true;
        assert!(
            !restricted.replay_snapshot().unwrap().contains(HIDDEN),
            "retention must not expose hidden configured approvals"
        );
        original.context_protectable = true;
        original.dependencies.insert("urn:test:support".into());
        let snapshot = original.replay_snapshot().unwrap();
        let mut current = original.clone();
        current.capture_t = 8;
        current.commitment = ContentHash::of_bytes(b"new head");
        current.restore_replay_snapshot(&snapshot).unwrap();
        assert_eq!(current.commitment(), original.commitment());
        assert_eq!(
            current.capture_t, 8,
            "replay release fence must remain current"
        );
        assert_eq!(current.replay_snapshot().unwrap(), snapshot);
        let mut revoked = original.clone();
        revoked.dependencies.clear();
        assert!(revoked.restore_replay_snapshot(&snapshot).is_err());
        let mut ambiguous = original.clone();
        ambiguous
            .identifier_index
            .get_mut(&(ID.into(), "A-1".into()))
            .unwrap()
            .insert(ALICE_B.into());
        assert!(ambiguous.restore_replay_snapshot(&snapshot).is_err());
        let mut changed = original.clone();
        changed.entities.get_mut(ALICE_A).unwrap().labels.clear();
        assert!(changed.restore_replay_snapshot(&snapshot).is_err());
        let mut unapproved = original.clone();
        unapproved.approved.clear();
        assert!(unapproved.restore_replay_snapshot(&snapshot).is_err());
    }

    #[test]
    fn empty_approval_means_empty_and_does_not_auto_promote() {
        let gazetteer = gazetteer(&[], true);
        assert!(gazetteer.is_empty());
        assert_eq!(gazetteer.describe(HIDDEN), None);
    }

    #[test]
    fn equal_labels_remain_ambiguous_and_never_resolve_identity() {
        let gazetteer = gazetteer(&[ALICE_A, ALICE_B], false);
        let mentions = gazetteer.known_mentions("Meet Alice Holdings today");
        assert_eq!(mentions.len(), 1);
        assert_eq!(mentions[0].start, 5);
        assert_eq!(mentions[0].candidate_iris, vec![ALICE_A, ALICE_B]);
        assert_eq!(
            gazetteer.resolve_known_iri(ALICE_A, &[]),
            KnownIriResolution::IdentifierRequired
        );
        assert_eq!(
            gazetteer.resolve_known_iri(
                ALICE_A,
                &[IdentifierProbe {
                    predicate: RDFS_LABEL.into(),
                    value: "Alice Holdings".into(),
                }]
            ),
            KnownIriResolution::IdentifierMismatch
        );
    }

    #[test]
    fn source_identifier_uniquely_retains_known_iri() {
        let gazetteer = gazetteer(&[ALICE_A, ALICE_B], false);
        assert_eq!(
            gazetteer.resolve_known_iri(
                ALICE_B,
                &[IdentifierProbe {
                    predicate: ID.into(),
                    value: "B-2".into(),
                }]
            ),
            KnownIriResolution::Resolved {
                iri: ALICE_B.into()
            }
        );
        assert_eq!(
            gazetteer.resolve_known_iri(
                ALICE_A,
                &[IdentifierProbe {
                    predicate: ID.into(),
                    value: "B-2".into(),
                }]
            ),
            KnownIriResolution::IdentifierMismatch
        );
    }

    #[test]
    fn ineligible_and_hidden_entities_do_not_leak() {
        let gazetteer = gazetteer(&[ALICE_A, HIDDEN, INELIGIBLE], false);
        assert_eq!(gazetteer.len(), 1);
        assert!(gazetteer.search("secret", 10).is_empty());
        assert!(gazetteer.search("wrong class", 10).is_empty());
        assert_eq!(
            gazetteer.ctxql_entities(EntityLookupRequest::Describe { iri: HIDDEN.into() }),
            EntityLookupResponse::NotFound
        );
        assert_eq!(gazetteer.describe(INELIGIBLE), None);
    }

    #[test]
    fn review_graph_is_excluded_and_unicode_offsets_are_bytes() {
        let gazetteer = gazetteer(&[ALICE_A, REVIEW_ENTITY], false);
        let mention = gazetteer
            .known_mentions("É — Alice Holdings")
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(mention.start, "É — ".len());
        assert_eq!(mention.end, "É — Alice Holdings".len());
        let shifted = gazetteer.known_mentions_at("Alice Holdings", 37);
        assert_eq!((shifted[0].start, shifted[0].end), (37, 51));
        assert_eq!(gazetteer.describe(REVIEW_ENTITY), None);
    }

    #[test]
    fn duplicate_or_unsorted_approvals_are_rejected() {
        assert!(validate_approvals(&[ALICE_B.into(), ALICE_A.into()]).is_err());
        assert!(validate_approvals(&[ALICE_A.into(), ALICE_A.into()]).is_err());
    }
}
