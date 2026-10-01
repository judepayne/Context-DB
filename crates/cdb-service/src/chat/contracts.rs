use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmptyRequest {}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatQueryRequest {
    pub query: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatSourceRequest {
    pub reference: String,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChatOntologyRequest {
    pub operation: String,
    pub query: String,
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub limit: Option<usize>,
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub kind: Option<String>,
}

fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactBinding {
    pub iri: String,
    pub version: String,
    pub hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SnapshotBinding {
    pub backend: String,
    pub authority: String,
    pub graph: String,
    pub revision: String,
    pub receipt: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ChatLabel {
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ChatNode {
    pub iri: String,
    pub display_label: String,
    pub labels: Vec<ChatLabel>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChatObject {
    Entity {
        iri: String,
    },
    Literal {
        value: serde_json::Value,
        datatype: String,
        language: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct ChatClaim {
    pub citation: String,
    pub claim_id: String,
    pub subject: String,
    pub predicate: String,
    pub object: ChatObject,
    pub metadata: serde_json::Value,
    pub sources: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChatSourceDescriptor {
    pub citation: Option<String>,
    pub claim_citation: String,
    pub reference: serde_json::Value,
    pub resolvable: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChatQueryResult {
    pub schema: &'static str,
    pub graph_permissions: &'static str,
    pub result_id: String,
    pub snapshot: SnapshotBinding,
    pub query_config: ArtifactBinding,
    pub profile_selector: Option<String>,
    pub profile: Option<ArtifactBinding>,
    pub complete: bool,
    pub nodes: Vec<ChatNode>,
    pub claims: Vec<ChatClaim>,
    pub paths: serde_json::Value,
    pub diagnostics: serde_json::Value,
    pub source_references: Vec<ChatSourceDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evicted_result_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ChatDiagnostic {
    Incomplete,
    TooBroad {
        cap: &'static str,
    },
    Capacity,
    #[serde(rename = "capacity")]
    CapacityAt {
        stage: &'static str,
    },
    Timeout,
    Cancelled,
    Denied,
    Invalid,
    Unavailable,
    SourceTooLarge,
    InventoryChanged,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ChatQueryOutcome {
    Inventory(Box<super::inventory::InventoryPage>),
    Complete(Box<ChatQueryResult>),
    Diagnostic(ChatDiagnostic),
}

#[derive(Clone, Debug, Serialize)]
pub struct ChatSourceResult {
    pub schema: &'static str,
    pub citation: String,
    pub reference: serde_json::Value,
    pub content: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ChatSourceOutcome {
    Complete(ChatSourceResult),
    Diagnostic(ChatDiagnostic),
}

#[derive(Clone, Debug, Serialize)]
pub struct ChatCapabilities {
    pub schema: &'static str,
    pub graph_permissions: &'static str,
    pub stored_predicate_fields: bool,
    pub restricted_compiler: bool,
    pub approximate_explicit_labels: bool,
    pub custom_predicates: bool,
    pub inventory: Option<&'static str>,
    pub ontology: &'static str,
    pub source_reads: &'static str,
    pub max_nodes: usize,
    pub max_claims: usize,
    pub max_work: usize,
    pub max_response_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_closed_and_incomplete_outcomes_never_carry_handles() {
        assert!(serde_json::from_str::<ChatQueryRequest>(r#"{"query":"{}"}"#).is_ok());
        assert!(serde_json::from_str::<ChatQueryRequest>(
            r#"{"query":"{}","principal":"urn:forged"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ChatQueryRequest>(
            r#"{"query":"{}","unsafe-direct-projection":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ChatSourceRequest>(
            r#"{"reference":"S1","source_id":"urn:forged"}"#
        )
        .is_err());
        let value =
            serde_json::to_value(ChatQueryOutcome::Diagnostic(ChatDiagnostic::Incomplete)).unwrap();
        assert_eq!(value["status"], "incomplete");
        assert!(value.get("result_id").is_none());
    }

    #[test]
    fn ontology_request_omits_absent_optional_fields() {
        for input in [
            r#"{"operation":"search","query":"loan"}"#,
            r#"{"operation":"vocabulary_status","query":"https://example.com/vocab"}"#,
        ] {
            let request: ChatOntologyRequest = serde_json::from_str(input).unwrap();
            let encoded = serde_json::to_value(request).unwrap();
            assert!(encoded.get("limit").is_none());
            assert!(encoded.get("kind").is_none());
        }
    }

    #[test]
    fn ontology_request_preserves_values_and_rejects_explicit_nulls() {
        let request: ChatOntologyRequest = serde_json::from_str(
            r#"{"operation":"search","query":"loan","limit":5,"kind":"class"}"#,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "operation": "search",
                "query": "loan",
                "limit": 5,
                "kind": "class"
            })
        );

        for invalid in [
            r#"{"operation":"search","query":"loan","limit":null}"#,
            r#"{"operation":"search","query":"loan","kind":null}"#,
            r#"{"operation":"search","query":"loan","limit":"5"}"#,
            r#"{"operation":"search","query":"loan","kind":5}"#,
        ] {
            assert!(serde_json::from_str::<ChatOntologyRequest>(invalid).is_err());
        }
    }
}
