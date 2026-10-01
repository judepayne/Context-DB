//! Chat-only, bounded inventory projection of a complete authorized engine result.
//! This is not a CTXQL grammar extension or a second authorization implementation.
use super::contracts::{ChatQueryOutcome, ChatQueryResult};
use crate::graph_query::AuthorizedQuery;
use cdb_core::{claim::ClaimObject, id::Iri, CanonicalValue as V, Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const SCHEMA: &str = "ctxql.chat-inventory/v1";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const NAMES: &[&str] = &[
    "http://www.w3.org/2000/01/rdf-schema#label",
    "http://www.w3.org/2004/02/skos/core#prefLabel",
    "http://www.w3.org/2004/02/skos/core#altLabel",
    "https://www.omg.org/spec/Commons/Designators/hasTextualName",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryCursor {
    commitment: String,
    offset: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Classes,
    Entities,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryRequest {
    schema: String,
    operation: Operation,
    #[serde(default)]
    classes: Vec<String>,
    #[serde(default)]
    relations: Vec<String>,
    #[serde(default = "default_page_size")]
    page_size: usize,
    #[serde(default)]
    cursor: Option<InventoryCursor>,
}
fn default_page_size() -> usize {
    20
}

fn cursor_binding(cursor: Option<&InventoryCursor>) -> Result<Option<Vec<u8>>> {
    cursor
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|_| Error::invalid("inventory cursor encoding"))
}

impl InventoryRequest {
    pub(super) fn cursor_binding(&self) -> Result<Option<Vec<u8>>> {
        cursor_binding(self.cursor.as_ref())
    }

    pub(super) fn parse(query: &str) -> Result<Option<Self>> {
        let Ok(value) = serde_json::from_str::<Value>(query) else {
            return Ok(None);
        };
        if value.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
            return Ok(None);
        }
        // Preserve the closed canonical JSON contract, including duplicate-key rejection.
        V::parse(query.as_bytes(), cdb_core::Limits::default())?;
        let mut request: Self =
            serde_json::from_value(value).map_err(|_| Error::invalid("inventory request"))?;
        if request.page_size == 0
            || request.page_size > 25
            || request.classes.len() > 32
            || request.relations.len() > 16
        {
            return Err(Error::invalid("inventory bounds"));
        }
        match request.operation {
            Operation::Classes if !request.classes.is_empty() || !request.relations.is_empty() => {
                return Err(Error::invalid("class inventory has no filters"))
            }
            Operation::Entities if request.classes.is_empty() => {
                return Err(Error::invalid("entity inventory requires explicit classes"))
            }
            _ => {}
        }
        for iri in request.classes.iter().chain(&request.relations) {
            Iri::new(iri)?;
        }
        request.classes.sort();
        request.classes.dedup();
        request.relations.sort();
        request.relations.dedup();
        Ok(Some(request))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct InventoryPage {
    pub schema: &'static str,
    pub operation: Operation,
    /// Complete count over the current authorized, active explicit-type view.
    pub total: usize,
    pub classes: Vec<String>,
    pub relations: Vec<String>,
    pub entities_with_relations: Option<usize>,
    pub offset: usize,
    pub page_complete: bool,
    pub next_cursor: Option<InventoryCursor>,
    pub entries: Vec<Value>,
    /// Only this page's supporting claims; compact metadata, ordinary C/S handles.
    pub evidence: ChatQueryResult,
}

pub(super) struct Projection {
    request: InventoryRequest,
    total: usize,
    entities_with_relations: Option<usize>,
    offset: usize,
    next_cursor: Option<InventoryCursor>,
    entries: Vec<Value>,
    pub execution: AuthorizedQuery,
}

impl Projection {
    pub(super) fn cursor_binding(&self) -> Result<Option<Vec<u8>>> {
        cursor_binding(self.next_cursor.as_ref())
    }

    pub(super) fn finish(self, evidence: ChatQueryResult) -> ChatQueryOutcome {
        ChatQueryOutcome::Inventory(Box::new(InventoryPage {
            schema: "ctxql.chat-inventory-result/v1",
            operation: self.request.operation,
            total: self.total,
            classes: self.request.classes,
            relations: self.request.relations,
            entities_with_relations: self.entities_with_relations,
            offset: self.offset,
            page_complete: true,
            next_cursor: self.next_cursor,
            entries: self.entries,
            evidence,
        }))
    }
}

/// ChatState first verifies the last issued cursor's complete binding. It is
/// never a read capability: every page reconstructs the current authorized
/// engine result, and changed data/visibility/scope invalidates continuation.
pub(super) fn project(
    request: InventoryRequest,
    mut execution: AuthorizedQuery,
) -> Result<Projection> {
    let claims = execution.response.field("claims")?.as_array()?;
    let mut records = Vec::new();
    for claim in claims {
        let meta = claim.field("meta")?;
        if meta.field("lifecycle_state")?.as_str()? != "active" {
            continue;
        }
        records.push((meta.field("claim_id")?.as_str()?.to_owned(), claim.clone()));
    }
    records.sort_by(|a, b| a.0.cmp(&b.0));
    let mut scope = request.clone();
    scope.cursor = None;
    scope.page_size = 0;
    let binding = json!({
        "scope": scope,
        "snapshot": super::reads::snapshot_binding(&execution.snapshot),
        "config": super::reads::artifact_binding(&execution.query_config),
        "claims": records.iter().map(|(_,v)| super::reads::value_json(v)).collect::<Result<Vec<_>>>()?,
    });
    let commitment = cdb_core::id::ContentHash::of_bytes(
        &serde_json::to_vec(&binding).map_err(|_| Error::invalid("inventory binding"))?,
    )
    .as_str()
    .to_owned();
    if request
        .cursor
        .as_ref()
        .is_some_and(|cursor| cursor.commitment != commitment)
    {
        return Err(Error::new(
            ErrorKind::Snapshot,
            "inventory changed; restart without cursor",
        ));
    }
    let mut by_subject: BTreeMap<String, Vec<(String, V)>> = BTreeMap::new();
    let mut types: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (id, value) in &records {
        let meta = value.field("meta")?;
        let subject = meta.field("subject_id")?.as_str()?.to_owned();
        if meta.field("relation")?.as_str()? == RDF_TYPE {
            if let ClaimObject::Entity(class) = ClaimObject::from_value(meta.field("object_id")?)? {
                types
                    .entry(subject.clone())
                    .or_default()
                    .insert(class.as_str().to_owned());
            }
        }
        by_subject
            .entry(subject)
            .or_default()
            .push((id.clone(), value.clone()));
    }
    let mut entries = Vec::<(Value, BTreeSet<String>)>::new();
    let mut with_relations = 0;
    match request.operation {
        Operation::Classes => {
            let mut counts = BTreeMap::<String, usize>::new();
            for classes in types.values() {
                for class in classes {
                    *counts.entry(class.clone()).or_default() += 1;
                }
            }
            entries.extend(
                counts
                    .into_iter()
                    .map(|(iri, count)| (json!({"iri":iri,"entity_count":count}), BTreeSet::new())),
            );
        }
        Operation::Entities => {
            for (subject, classes) in &types {
                if !request.classes.iter().any(|class| classes.contains(class)) {
                    continue;
                }
                let mut supports = BTreeSet::new();
                let mut names = BTreeSet::new();
                let mut relations = Vec::new();
                for (id, value) in &by_subject[subject] {
                    let meta = value.field("meta")?;
                    let predicate = meta.field("relation")?.as_str()?;
                    let object = ClaimObject::from_value(meta.field("object_id")?)?;
                    if predicate == RDF_TYPE {
                        supports.insert(id.clone());
                    }
                    if NAMES.contains(&predicate) {
                        if let ClaimObject::Literal(literal) = &object {
                            if matches!(
                                literal.datatype().as_str(),
                                "http://www.w3.org/2001/XMLSchema#string"
                                    | "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString"
                            ) {
                                if let Ok(name) = literal.value().as_str() {
                                    names.insert(name.to_owned());
                                    supports.insert(id.clone());
                                }
                            }
                        }
                    }
                    if request
                        .relations
                        .iter()
                        .any(|relation| relation == predicate)
                    {
                        supports.insert(id.clone());
                        let mut related_literals = Vec::new();
                        if let ClaimObject::Entity(entity) = &object {
                            if let Some(related) = by_subject.get(entity.as_str()) {
                                for (related_id, related_value) in related {
                                    let related_meta = related_value.field("meta")?;
                                    if matches!(
                                        ClaimObject::from_value(related_meta.field("object_id")?)?,
                                        ClaimObject::Literal(_)
                                    ) {
                                        supports.insert(related_id.clone());
                                        related_literals.push(related_id.clone());
                                    }
                                }
                            }
                        }
                        relations.push(json!({"claim_id":id,"predicate":predicate,
                            "object":super::reads::value_json(meta.field("object_id")?)?,
                            "related_literal_claims":related_literals}));
                    }
                }
                if !relations.is_empty() {
                    with_relations += 1;
                }
                entries.push((
                    json!({"iri":subject,"names":names,"types":classes,"relations":relations}),
                    supports,
                ));
            }
        }
    }
    let total = entries.len();
    let offset = request.cursor.as_ref().map_or(0, |cursor| cursor.offset);
    if offset > total {
        return Err(Error::invalid("inventory cursor offset"));
    }
    let end = offset.saturating_add(request.page_size).min(total);
    let next_cursor = (end < total).then_some(InventoryCursor {
        commitment,
        offset: end,
    });
    let mut support_ids = BTreeSet::new();
    let entries = entries
        .into_iter()
        .skip(offset)
        .take(end - offset)
        .map(|(entry, ids)| {
            support_ids.extend(ids);
            entry
        })
        .collect();
    let selected = records
        .into_iter()
        .filter_map(|(id, value)| support_ids.contains(&id).then_some(value))
        .collect();
    let mut response = execution.response.as_object()?.clone();
    response.insert("claims".into(), V::Array(selected));
    response.insert("paths".into(), V::Array(Vec::new()));
    execution.response = V::Object(response);
    // Names below are derived from the same active claims, not stale lexical supports.
    execution.labels.clear();
    let entities_with_relations = matches!(request.operation, Operation::Entities)
        .then_some(with_relations)
        .filter(|_| !request.relations.is_empty());
    Ok(Projection {
        request,
        total,
        entities_with_relations,
        offset,
        next_cursor,
        entries,
        execution,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_chat_envelopes_are_valid() {
        let skill = include_str!("../../../../assets/pi/skills/ctxql-query/SKILL.md");
        let mut inventory = 0;
        for block in skill.split("```json\n").skip(1) {
            if InventoryRequest::parse(block.split("\n```").next().unwrap())
                .unwrap()
                .is_some()
            {
                inventory += 1;
            }
        }
        assert_eq!(inventory, 2);
    }

    #[test]
    fn inventory_counts_only_active_types_not_retired_claims() {
        use cdb_core::{
            artifact::ArtifactRef,
            id::*,
            snapshot::{GraphPin, SnapshotRef},
        };
        let mut claims = ["active", "retracted", "superseded", "contradicted"]
            .into_iter()
            .enumerate()
            .map(|(i, state)| {
                json!({"meta":{"claim_id":format!("urn:claim:{i}"),
                "subject_id":format!("urn:entity:{i}"),"relation":RDF_TYPE,
                "object_id":"urn:class:Party","lifecycle_state":state}})
            })
            .collect::<Vec<_>>();
        claims.push(
            json!({"meta":{"claim_id":"urn:claim:non-text-name","subject_id":"urn:entity:0",
            "relation":NAMES[0],"lifecycle_state":"active",
            "object_id":{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#anyURI",
                "value":"https://example.org/","language":null}}}),
        );
        let execution = AuthorizedQuery {
            dependencies: BTreeSet::new(),
            labels: BTreeMap::new(),
            profile: None,
            response: V::parse(
                &serde_json::to_vec(&json!({"claims":claims})).unwrap(),
                cdb_core::Limits::default(),
            )
            .unwrap(),
            snapshot: SnapshotRef::new(
                BackendId::new("semantic").unwrap(),
                GraphPin::new(
                    AuthorityId::new("authority").unwrap(),
                    GraphId::new("graph").unwrap(),
                    VersionId::new("1").unwrap(),
                    ResourceId::new("receipt").unwrap(),
                ),
            ),
            query_config: ArtifactRef::new(
                Iri::new("urn:config:test").unwrap(),
                VersionId::new("1").unwrap(),
                ContentHash::of_bytes(b"config"),
            ),
        };
        let request = InventoryRequest::parse(
            &json!({"schema":SCHEMA,"operation":"entities",
            "classes":["urn:class:Party"],"relations":[NAMES[0]]})
            .to_string(),
        )
        .unwrap()
        .unwrap();
        let result = project(request, execution).unwrap();
        assert_eq!(result.total, 1);
        assert_eq!(result.entries[0]["iri"], "urn:entity:0");
        assert_eq!(result.entries[0]["names"], json!([]));
        assert_eq!(
            result.entries[0]["relations"].as_array().unwrap().len(),
            1,
            "non-text name literals remain ordinary facts when explicitly requested"
        );
        assert_eq!(
            result
                .execution
                .response
                .field("claims")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn inventory_envelopes_are_closed_bounded_and_not_general_query_syntax() {
        assert!(InventoryRequest::parse(r#"{"about":[]}"#)
            .unwrap()
            .is_none());
        assert!(InventoryRequest::parse(
            r#"{"schema":"ctxql.chat-inventory/v1","operation":"classes"}"#
        )
        .unwrap()
        .is_some());
        for extra in [
            json!({"page_size":0}),
            json!({"page_size":26}),
            json!({"page_size":null}),
            json!({"principal":"admin"}),
            json!({"classes":["urn:class:X"]}),
        ] {
            let mut value = json!({"schema":SCHEMA,"operation":"classes"});
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(InventoryRequest::parse(&value.to_string()).is_err());
        }
        assert!(InventoryRequest::parse(r#"{"schema":"ctxql.chat-inventory/v1","operation":"classes","page_size":1,"page_size":2}"#).is_err());
        assert!(InventoryRequest::parse(
            r#"{"schema":"ctxql.chat-inventory/v1","operation":"entities","classes":[]}"#
        )
        .is_err());
    }
}
