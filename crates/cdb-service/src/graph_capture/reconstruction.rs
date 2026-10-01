//! Offline deterministic replay of private workspace interactions. No provider,
//! native graph query, source converter, or admission capability enters here.
use crate::graph_workspace::{
    ApplyRequest, DocumentContext, Handle, IssuedGraph, ViewKind, Workspace, WorkspaceLimits,
};
use cdb_core::{id::ContentHash, CanonicalValue as V, Error, Limits, Result};
use serde_json::{json as json_value, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const LEAF_SCHEMA_V1: &str = "ctxql-graph-transcript-leaf/v1";
const STATE_SCHEMA_V1: &str = "ctxql-graph-workspace-state/v1";
const WORKSPACE_SCHEMA_V1: &str = "ctxql.graph-workspace/v1";

struct Evidence<'a>(&'a BTreeSet<String>);
impl DocumentContext for Evidence<'_> {
    fn owns_evidence(&self, handle: &str) -> bool {
        self.0.contains(handle)
    }
    fn is_cancelled(&self) -> bool {
        false
    }
}

fn json(value: &V) -> Result<Value> {
    serde_json::from_slice(&value.canonical_bytes(Limits::default())?)
        .map_err(|_| Error::invalid("workspace replay encoding"))
}
fn invalid() -> Error {
    Error::invalid("workspace replay mismatch")
}
fn workspace<T>(result: crate::graph_workspace::Result<T>) -> Result<T> {
    result.map_err(|_| invalid())
}
fn object(value: &Value) -> Result<&Map<String, Value>> {
    value.as_object().ok_or_else(invalid)
}
fn closed(fields: &Map<String, Value>, allowed: &[&str]) -> Result<()> {
    if fields.len() != allowed.len() || fields.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid());
    }
    Ok(())
}
fn optional_usize(value: Option<&Value>) -> Result<Option<usize>> {
    value
        .map(|value| usize::try_from(value.as_u64().ok_or_else(invalid)?).map_err(|_| invalid()))
        .transpose()
}
fn exact_response(recorded: &str, regenerated: Value) -> Result<()> {
    // The retained bytes remain the disclosure commitment. Regeneration only
    // proves that this version of the deterministic contract produces them.
    if serde_json::to_vec(&regenerated).map_err(|_| invalid())? != recorded.as_bytes() {
        return Err(invalid());
    }
    Ok(())
}
fn ok_response(result: Value) -> Value {
    json_value!({
        "schema": "ctxql-graph-playground-result/v1",
        "status": "ok",
        "result": result,
    })
}
fn error_response_code(response: &Value, response_text: &str) -> Result<&'static str> {
    let fields = object(response)?;
    closed(fields, &["schema", "status", "code"])?;
    let code = match response["code"].as_str() {
        Some("access_denied") => "access_denied",
        Some("policy_changed") => "policy_changed",
        Some("preparation_failed") => "preparation_failed",
        _ => return Err(invalid()),
    };
    if response["schema"].as_str() != Some("ctxql-graph-tool-error/v1")
        || response["status"].as_str() != Some("error")
    {
        return Err(invalid());
    }
    exact_response(
        response_text,
        json_value!({
            "schema": "ctxql-graph-tool-error/v1",
            "status": "error",
            "code": code,
        }),
    )?;
    Ok(code)
}
fn workspace_error_code(error: &crate::graph_workspace::Error) -> &'static str {
    match error {
        crate::graph_workspace::Error::ForeignHandle
        | crate::graph_workspace::Error::ForeignEvidence => "access_denied",
        _ => "preparation_failed",
    }
}
fn account_recorded_error(workspace_state: &mut Workspace, response_text: &str) -> Result<()> {
    workspace(workspace_state.finish_call_bytes(response_text.len()))
}

pub(crate) fn reconstruct_workspace(
    leaves: &[V],
    payloads: &BTreeMap<ContentHash, V>,
    final_state: &V,
    evidence: &BTreeSet<String>,
) -> Result<()> {
    let state = json(final_state)?;
    let state_fields = object(&state)?;
    closed(
        state_fields,
        &[
            "schema",
            "issuer",
            "session_id",
            "revision",
            "limits",
            "graphs",
            "records",
            "idempotency",
            "counters",
            "next",
        ],
    )?;
    if state["schema"].as_str() != Some(STATE_SCHEMA_V1) {
        return Err(invalid());
    }
    let limits: WorkspaceLimits =
        serde_json::from_value(state["limits"].clone()).map_err(|_| invalid())?;
    let session = state["session_id"].as_str().ok_or_else(invalid)?;
    let issuer = state["issuer"].as_str().ok_or_else(invalid)?;
    let mut workspace = Workspace::new(issuer, session, limits).map_err(|_| invalid())?;
    let document = Evidence(evidence);

    for leaf in leaves {
        if leaf.field("schema")?.as_str()? != LEAF_SCHEMA_V1
            || workspace.revision() != leaf.field("revision_before")?.u64()?
        {
            return Err(invalid());
        }
        let request_text = leaf.field("request")?.as_str()?;
        let response_text = leaf.field("response")?.as_str()?;
        let request: Value = serde_json::from_str(request_text).map_err(|_| invalid())?;
        let response: Value = serde_json::from_str(response_text).map_err(|_| invalid())?;
        let result_kind = leaf.field("result_kind")?.as_str()?;

        match leaf.field("capability")?.as_str()? {
            "graph_query" => replay_query(
                &mut workspace,
                leaf,
                payloads,
                &request,
                &response,
                response_text,
                result_kind,
            )?,
            "graph_playground" => replay_playground(
                &mut workspace,
                &document,
                &request,
                &response,
                response_text,
                result_kind,
            )?,
            _ => return Err(invalid()),
        }
        if workspace.revision() != leaf.field("revision_after")?.u64()? {
            return Err(invalid());
        }
    }

    let reconstructed = workspace.capture_projection()?;
    // Compare the complete state. Counters are replayed rather than trusted:
    // calls, retries, queries, diagnostics, response bytes and retained state
    // all participate in this equality.
    if reconstructed != *final_state {
        return Err(invalid());
    }
    Ok(())
}

fn replay_query(
    workspace_state: &mut Workspace,
    leaf: &V,
    payloads: &BTreeMap<ContentHash, V>,
    request: &Value,
    response: &Value,
    response_text: &str,
    result_kind: &str,
) -> Result<()> {
    let request_fields = object(request)?;
    if request_fields.keys().any(|key| {
        !matches!(
            key.as_str(),
            "query" | "max_nodes" | "max_claims" | "max_response_bytes" | "timeout_ms"
        )
    }) {
        return Err(invalid());
    }
    let query = request_fields
        .get("query")
        .and_then(Value::as_str)
        .filter(|query| !query.is_empty() && query.len() <= 32 * 1024)
        .ok_or_else(invalid)?;
    for name in [
        "max_nodes",
        "max_claims",
        "max_response_bytes",
        "timeout_ms",
    ] {
        if let Some(value) = request_fields.get(name) {
            value.as_u64().ok_or_else(invalid)?;
        }
    }
    workspace(workspace_state.begin_call(query.len(), true))?;

    match result_kind {
        "graph" => {
            let response_fields = object(response)?;
            closed(
                response_fields,
                &[
                    "schema",
                    "status",
                    "handle",
                    "snapshot",
                    "node_count",
                    "claim_count",
                    "complete",
                    "overview",
                ],
            )?;
            if response["schema"].as_str() != Some("ctxql-graph-query-result/v1")
                || response["status"].as_str() != Some("graph")
                || response["complete"].as_bool() != Some(true)
            {
                return Err(invalid());
            }
            let root = ContentHash::parse(leaf.field("graph_payload_root")?.as_str()?)?;
            let payload = payloads.get(&root).ok_or_else(invalid)?;
            if ContentHash::of_bytes(&payload.canonical_bytes(Limits::default())?) != root {
                return Err(invalid());
            }
            let graph: IssuedGraph =
                serde_json::from_value(json(payload)?).map_err(|_| invalid())?;
            let dependencies = graph
                .claims
                .iter()
                .flat_map(|claim| claim.dependencies.iter())
                .chain(graph.nodes.iter().flat_map(|node| node.dependencies.iter()))
                .cloned()
                .collect::<BTreeSet<_>>();
            let recorded_dependencies = leaf
                .field("claim_dependencies")?
                .as_array()?
                .iter()
                .map(|value| Ok(value.as_str()?.to_owned()))
                .collect::<Result<BTreeSet<_>>>()?;
            if dependencies != recorded_dependencies {
                return Err(invalid());
            }
            let node_count = graph.nodes.len();
            let claim_count = graph.claims.len();
            let snapshot = graph.snapshot.clone();
            let graph_bytes = payload.canonical_bytes(Limits::default())?.len();
            let overview_nodes = graph.nodes.clone();
            let handle = workspace(workspace_state.register_graph(graph))?;
            workspace(workspace_state.finish_call_bytes(graph_bytes))?;
            let mut overview = format!(
                "COMPLETE GRAPH {} / {} nodes / {} claims\n",
                handle.0, node_count, claim_count
            );
            for node in overview_nodes.iter().take(8) {
                overview.push_str(&format!(
                    "NODE {}: {} [{}]\n",
                    node.key, node.label, node.canonical_iri
                ));
            }
            let omitted = node_count.saturating_sub(8);
            if omitted != 0 {
                overview.push_str(&format!(
                    "VIEW ONLY: {omitted} nodes omitted from overview\n"
                ));
            }
            exact_response(
                response_text,
                json_value!({
                    "schema": "ctxql-graph-query-result/v1",
                    "status": "graph",
                    "handle": handle,
                    "snapshot": snapshot,
                    "node_count": node_count,
                    "claim_count": claim_count,
                    "complete": true,
                    "overview": overview,
                }),
            )?;
        }
        "diagnostic" => {
            let fields = object(response)?;
            closed(fields, &["schema", "status", "diagnostic"])?;
            if response["schema"].as_str() != Some("ctxql-graph-query-result/v1")
                || response["status"].as_str() != Some("diagnostic")
                || !valid_diagnostic(&response["diagnostic"])
            {
                return Err(invalid());
            }
            // Session accounting serializes SessionQueryResult, before the
            // bridge renders its public response envelope.
            let accounted = serde_json::to_vec(&json_value!({
                "Diagnostic": response["diagnostic"].clone()
            }))
            .map_err(|_| invalid())?
            .len();
            workspace(workspace_state.finish_call_bytes(accounted))?;
            exact_response(response_text, response.clone())?;
        }
        "error" => {
            // Queries are not rerun during replay. The operation contract fixes
            // begin-call accounting, while the retained public envelope fixes
            // bounded response accounting without relying on private errors.
            error_response_code(response, response_text)?;
            account_recorded_error(workspace_state, response_text)?;
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

fn valid_diagnostic(value: &Value) -> bool {
    match value {
        Value::String(name) => matches!(name.as_str(), "Incomplete" | "Capacity"),
        Value::Object(fields) if fields.len() == 1 => fields
            .get("QueryTooBroad")
            .and_then(Value::as_object)
            .is_some_and(|detail| {
                detail.len() == 1
                    && detail
                        .get("cap")
                        .and_then(Value::as_str)
                        .is_some_and(|cap| matches!(cap, "nodes" | "claims"))
            }),
        _ => false,
    }
}

fn replay_playground(
    workspace_state: &mut Workspace,
    document: &Evidence<'_>,
    request: &Value,
    response: &Value,
    response_text: &str,
    result_kind: &str,
) -> Result<()> {
    let request_fields = object(request)?;
    let operation = request_fields
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let expected_kind = match operation {
        "import" | "release_graph" | "apply" => "mutation",
        "view" | "inspect" => "view",
        "check" => "check",
        _ => return Err(invalid()),
    };
    if result_kind == "error" {
        return replay_playground_error(
            workspace_state,
            document,
            request_fields,
            operation,
            response,
            response_text,
        );
    }
    if result_kind != expected_kind
        || response["schema"].as_str() != Some("ctxql-graph-playground-result/v1")
        || response["status"].as_str() != Some("ok")
    {
        return Err(invalid());
    }
    let response_fields = object(response)?;
    closed(response_fields, &["schema", "status", "result"])?;

    let result = match operation {
        "import" => {
            closed(request_fields, &["operation", "handle"])?;
            let handle = request_handle(request_fields)?;
            let request_bytes = serde_json::to_vec(&handle).map_err(|_| invalid())?.len();
            workspace(workspace_state.begin_call(request_bytes, false))?;
            let value = serde_json::to_value(workspace(workspace_state.import_graph(&handle))?)
                .map_err(|_| invalid())?;
            let bytes = serde_json::to_vec(&value).map_err(|_| invalid())?.len();
            workspace(workspace_state.finish_call_bytes(bytes))?;
            value
        }
        "release_graph" => {
            closed(request_fields, &["operation", "handle"])?;
            let handle = request_handle(request_fields)?;
            let request_bytes = serde_json::to_vec(&handle).map_err(|_| invalid())?.len();
            workspace(workspace_state.begin_call(request_bytes, false))?;
            workspace(workspace_state.release_graph(&handle))?;
            workspace(workspace_state.finish_call_bytes(2))?;
            json_value!({"released": true})
        }
        "apply" => {
            closed(
                request_fields,
                &["operation", "expected_revision", "idempotency_key", "edits"],
            )?;
            let apply = ApplyRequest {
                schema: WORKSPACE_SCHEMA_V1.into(),
                session_id: workspace_state
                    .capture_projection()?
                    .field("session_id")?
                    .as_str()?
                    .to_owned(),
                expected_revision: request_fields["expected_revision"]
                    .as_u64()
                    .ok_or_else(invalid)?,
                idempotency_key: request_fields["idempotency_key"]
                    .as_str()
                    .ok_or_else(invalid)?
                    .to_owned(),
                edits: serde_json::from_value(request_fields["edits"].clone())
                    .map_err(|_| invalid())?,
            };
            let request_bytes = serde_json::to_vec(&apply).map_err(|_| invalid())?.len();
            workspace(workspace_state.begin_call(request_bytes, false))?;
            serde_json::to_value(workspace(
                workspace_state.apply_preaccounted(apply, document),
            )?)
            .map_err(|_| invalid())?
        }
        "view" => {
            if request_fields
                .keys()
                .any(|key| !matches!(key.as_str(), "operation" | "view" | "handle" | "max_bytes"))
            {
                return Err(invalid());
            }
            let kind = view_kind(request_fields)?;
            replay_view(
                workspace_state,
                kind,
                optional_usize(request_fields.get("max_bytes"))?,
            )?
        }
        "inspect" => {
            if request_fields
                .keys()
                .any(|key| !matches!(key.as_str(), "operation" | "handle" | "max_bytes"))
                || !request_fields.contains_key("handle")
            {
                return Err(invalid());
            }
            let kind = ViewKind::Neighbourhood {
                centre: request_handle(request_fields)?,
            };
            replay_view(
                workspace_state,
                kind,
                optional_usize(request_fields.get("max_bytes"))?,
            )?
        }
        "check" => {
            closed(request_fields, &["operation"])?;
            workspace(workspace_state.begin_call(2, false))?;
            let check = workspace(workspace_state.check())?;
            let value = serde_json::to_value(check).map_err(|_| invalid())?;
            let bytes = serde_json::to_vec(&value).map_err(|_| invalid())?.len();
            workspace(workspace_state.finish_call_bytes(bytes))?;
            value
        }
        _ => unreachable!("operation was closed above"),
    };
    exact_response(response_text, ok_response(result))
}

fn replay_playground_error(
    workspace_state: &mut Workspace,
    document: &Evidence<'_>,
    request_fields: &Map<String, Value>,
    operation: &str,
    response: &Value,
    response_text: &str,
) -> Result<()> {
    let recorded_code = error_response_code(response, response_text)?;
    let deterministic_error = match operation {
        "import" => {
            closed(request_fields, &["operation", "handle"])?;
            let handle = request_handle(request_fields)?;
            let request_bytes = serde_json::to_vec(&handle).map_err(|_| invalid())?.len();
            workspace(workspace_state.begin_call(request_bytes, false))?;
            let mut staged = workspace_state.clone();
            match staged.import_graph(&handle) {
                Err(error) => error,
                Ok(_) => return Err(invalid()),
            }
        }
        "release_graph" => {
            closed(request_fields, &["operation", "handle"])?;
            let handle = request_handle(request_fields)?;
            let request_bytes = serde_json::to_vec(&handle).map_err(|_| invalid())?.len();
            workspace(workspace_state.begin_call(request_bytes, false))?;
            let mut staged = workspace_state.clone();
            match staged.release_graph(&handle) {
                Err(error) => error,
                Ok(()) => return Err(invalid()),
            }
        }
        "apply" => {
            closed(
                request_fields,
                &["operation", "expected_revision", "idempotency_key", "edits"],
            )?;
            let apply = ApplyRequest {
                schema: WORKSPACE_SCHEMA_V1.into(),
                session_id: workspace_state
                    .capture_projection()?
                    .field("session_id")?
                    .as_str()?
                    .to_owned(),
                expected_revision: request_fields["expected_revision"]
                    .as_u64()
                    .ok_or_else(invalid)?,
                idempotency_key: request_fields["idempotency_key"]
                    .as_str()
                    .ok_or_else(invalid)?
                    .to_owned(),
                edits: serde_json::from_value(request_fields["edits"].clone())
                    .map_err(|_| invalid())?,
            };
            let request_bytes = serde_json::to_vec(&apply).map_err(|_| invalid())?.len();
            workspace(workspace_state.begin_call(request_bytes, false))?;
            let mut staged = workspace_state.clone();
            match staged.apply_preaccounted(apply, document) {
                Err(error) => error,
                Ok(_) => return Err(invalid()),
            }
        }
        "view" => {
            if request_fields
                .keys()
                .any(|key| !matches!(key.as_str(), "operation" | "view" | "handle" | "max_bytes"))
            {
                return Err(invalid());
            }
            let kind = view_kind(request_fields)?;
            let max_bytes = optional_usize(request_fields.get("max_bytes"))?;
            let request_bytes = serde_json::to_vec(&(kind.clone(), max_bytes))
                .map_err(|_| invalid())?
                .len();
            workspace(workspace_state.begin_call(request_bytes, false))?;
            let staged = workspace_state.clone();
            match staged.view(kind, max_bytes) {
                Err(error) => error,
                Ok(_) => return Err(invalid()),
            }
        }
        "inspect" => {
            if request_fields
                .keys()
                .any(|key| !matches!(key.as_str(), "operation" | "handle" | "max_bytes"))
                || !request_fields.contains_key("handle")
            {
                return Err(invalid());
            }
            let kind = ViewKind::Neighbourhood {
                centre: request_handle(request_fields)?,
            };
            let max_bytes = optional_usize(request_fields.get("max_bytes"))?;
            let request_bytes = serde_json::to_vec(&(kind.clone(), max_bytes))
                .map_err(|_| invalid())?
                .len();
            workspace(workspace_state.begin_call(request_bytes, false))?;
            let staged = workspace_state.clone();
            match staged.view(kind, max_bytes) {
                Err(error) => error,
                Ok(_) => return Err(invalid()),
            }
        }
        // A structural check cannot deterministically fail while the captured
        // workspace remains valid. Terminal/authority failures are not
        // accepted final-output replay states.
        "check" => return Err(invalid()),
        _ => return Err(invalid()),
    };
    if workspace_error_code(&deterministic_error) != recorded_code {
        return Err(invalid());
    }
    account_recorded_error(workspace_state, response_text)
}

fn request_handle(fields: &Map<String, Value>) -> Result<Handle> {
    Ok(Handle(
        fields
            .get("handle")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?
            .to_owned(),
    ))
}

fn view_kind(fields: &Map<String, Value>) -> Result<ViewKind> {
    match fields.get("view").and_then(Value::as_str) {
        Some("overview") if !fields.contains_key("handle") => Ok(ViewKind::Overview),
        Some("changes") if !fields.contains_key("handle") => Ok(ViewKind::Changes),
        Some("open_questions") if !fields.contains_key("handle") => Ok(ViewKind::OpenQuestions),
        Some("neighbourhood") => Ok(ViewKind::Neighbourhood {
            centre: request_handle(fields)?,
        }),
        _ => Err(invalid()),
    }
}

fn replay_view(
    workspace_state: &mut Workspace,
    kind: ViewKind,
    max_bytes: Option<usize>,
) -> Result<Value> {
    let request_bytes = serde_json::to_vec(&(kind.clone(), max_bytes))
        .map_err(|_| invalid())?
        .len();
    workspace(workspace_state.begin_call(request_bytes, false))?;
    let view = workspace(workspace_state.view(kind, max_bytes))?;
    let value = serde_json::to_value(view).map_err(|_| invalid())?;
    let bytes = serde_json::to_vec(&value).map_err(|_| invalid())?.len();
    workspace(workspace_state.finish_call_bytes(bytes))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_workspace::Edit;

    fn canonical(value: &Value) -> V {
        V::parse(&serde_json::to_vec(value).unwrap(), Limits::default()).unwrap()
    }

    fn capability_leaf(
        capability: &str,
        request: &Value,
        response: &Value,
        before: u64,
        after: u64,
        kind: &str,
    ) -> V {
        canonical(&json_value!({
            "schema": LEAF_SCHEMA_V1,
            "capability": capability,
            "request": serde_json::to_string(request).unwrap(),
            "response": serde_json::to_string(response).unwrap(),
            "result_kind": kind,
            "revision_before": before,
            "revision_after": after
        }))
    }

    fn leaf(request: &Value, response: &Value, before: u64, after: u64, kind: &str) -> V {
        capability_leaf("graph_playground", request, response, before, after, kind)
    }

    fn apply_wire() -> Value {
        json_value!({
            "operation":"apply", "expected_revision":0, "idempotency_key":"add-party",
            "edits":[{"op":"add_node", "temp_id":"party", "local_id":"party", "label":"Party", "evidence":["range:1"]}]
        })
    }

    fn production_apply(
        workspace: &mut Workspace,
        wire: &Value,
        evidence: &BTreeSet<String>,
    ) -> Value {
        let apply = ApplyRequest {
            schema: WORKSPACE_SCHEMA_V1.into(),
            session_id: "session".into(),
            expected_revision: wire["expected_revision"].as_u64().unwrap(),
            idempotency_key: wire["idempotency_key"].as_str().unwrap().into(),
            edits: serde_json::from_value::<Vec<Edit>>(wire["edits"].clone()).unwrap(),
        };
        workspace
            .begin_call(serde_json::to_vec(&apply).unwrap().len(), false)
            .unwrap();
        let result = workspace
            .apply_preaccounted(apply, &Evidence(evidence))
            .unwrap();
        ok_response(serde_json::to_value(result).unwrap())
    }

    fn production_view(workspace: &mut Workspace, wire: &Value) -> Value {
        let kind = ViewKind::Neighbourhood {
            centre: Handle(wire["handle"].as_str().unwrap().into()),
        };
        let max_bytes = wire
            .get("max_bytes")
            .and_then(Value::as_u64)
            .map(|v| v as usize);
        workspace
            .begin_call(
                serde_json::to_vec(&(kind.clone(), max_bytes))
                    .unwrap()
                    .len(),
                false,
            )
            .unwrap();
        let result = workspace.view(kind, max_bytes).unwrap();
        let value = serde_json::to_value(result).unwrap();
        workspace
            .finish_call_bytes(serde_json::to_vec(&value).unwrap().len())
            .unwrap();
        ok_response(value)
    }

    fn production_check(workspace: &mut Workspace) -> Value {
        workspace.begin_call(2, false).unwrap();
        let value = serde_json::to_value(workspace.check().unwrap()).unwrap();
        workspace
            .finish_call_bytes(serde_json::to_vec(&value).unwrap().len())
            .unwrap();
        ok_response(value)
    }

    fn production_apply_error(
        workspace: &mut Workspace,
        wire: &Value,
        evidence: &BTreeSet<String>,
    ) -> Value {
        let apply = ApplyRequest {
            schema: WORKSPACE_SCHEMA_V1.into(),
            session_id: "session".into(),
            expected_revision: wire["expected_revision"].as_u64().unwrap(),
            idempotency_key: wire["idempotency_key"].as_str().unwrap().into(),
            edits: serde_json::from_value::<Vec<Edit>>(wire["edits"].clone()).unwrap(),
        };
        workspace
            .begin_call(serde_json::to_vec(&apply).unwrap().len(), false)
            .unwrap();
        let mut staged = workspace.clone();
        assert!(staged
            .apply_preaccounted(apply, &Evidence(evidence))
            .is_err());
        let response = json_value!({
            "schema":"ctxql-graph-tool-error/v1",
            "status":"error",
            "code":"preparation_failed"
        });
        workspace
            .finish_call_bytes(serde_json::to_vec(&response).unwrap().len())
            .unwrap();
        response
    }

    fn production_import_error(workspace: &mut Workspace, wire: &Value) -> Value {
        let handle = Handle(wire["handle"].as_str().unwrap().into());
        workspace
            .begin_call(serde_json::to_vec(&handle).unwrap().len(), false)
            .unwrap();
        let mut staged = workspace.clone();
        assert!(staged.import_graph(&handle).is_err());
        let response = json_value!({
            "schema":"ctxql-graph-tool-error/v1",
            "status":"error",
            "code":"preparation_failed"
        });
        workspace
            .finish_call_bytes(serde_json::to_vec(&response).unwrap().len())
            .unwrap();
        response
    }

    #[test]
    fn regenerates_retry_inspect_and_check_with_exact_counters() {
        let mut workspace =
            Workspace::new("issuer", "session", WorkspaceLimits::default()).unwrap();
        let evidence = BTreeSet::from(["range:1".to_owned()]);
        let apply = apply_wire();
        let before = workspace.revision();
        let first = production_apply(&mut workspace, &apply, &evidence);
        let mut leaves = vec![leaf(
            &apply,
            &first,
            before,
            workspace.revision(),
            "mutation",
        )];

        let before = workspace.revision();
        let retry = production_apply(&mut workspace, &apply, &evidence);
        leaves.push(leaf(
            &apply,
            &retry,
            before,
            workspace.revision(),
            "mutation",
        ));

        let handle = first["result"]["handles"]["party"].as_str().unwrap();
        let inspect = json_value!({"operation":"inspect", "handle":handle, "max_bytes":2048});
        let before = workspace.revision();
        let inspected = production_view(&mut workspace, &inspect);
        leaves.push(leaf(
            &inspect,
            &inspected,
            before,
            workspace.revision(),
            "view",
        ));

        let check = json_value!({"operation":"check"});
        let before = workspace.revision();
        let checked = production_check(&mut workspace);
        leaves.push(leaf(
            &check,
            &checked,
            before,
            workspace.revision(),
            "check",
        ));

        let state = workspace.capture_projection().unwrap();
        reconstruct_workspace(&leaves, &BTreeMap::new(), &state, &evidence).unwrap();
        assert_eq!(json(&state).unwrap()["counters"]["tool_calls"], 4);
        assert!(
            reconstruct_workspace(&leaves, &BTreeMap::new(), &state, &BTreeSet::new()).is_err()
        );
    }

    #[test]
    fn regenerates_query_diagnostic_accounting_without_live_query() {
        let mut workspace =
            Workspace::new("issuer", "session", WorkspaceLimits::default()).unwrap();
        let request = json_value!({"query":"ABOUT entity:borrower"});
        let diagnostic = json_value!({"QueryTooBroad":{"cap":"nodes"}});
        let response = json_value!({
            "schema":"ctxql-graph-query-result/v1",
            "status":"diagnostic",
            "diagnostic":diagnostic
        });
        workspace
            .begin_call(request["query"].as_str().unwrap().len(), true)
            .unwrap();
        workspace
            .finish_call_bytes(
                serde_json::to_vec(&json_value!({"Diagnostic":diagnostic}))
                    .unwrap()
                    .len(),
            )
            .unwrap();
        let state = workspace.capture_projection().unwrap();
        let leaves = [capability_leaf(
            "graph_query",
            &request,
            &response,
            0,
            0,
            "diagnostic",
        )];
        reconstruct_workspace(&leaves, &BTreeMap::new(), &state, &BTreeSet::new()).unwrap();

        let mut tampered = json(&state).unwrap();
        tampered["counters"]["graph_queries"] = json_value!(0);
        assert!(reconstruct_workspace(
            &leaves,
            &BTreeMap::new(),
            &canonical(&tampered),
            &BTreeSet::new()
        )
        .is_err());
    }

    #[test]
    fn response_counter_and_renderer_tampering_fail_offline() {
        let mut workspace =
            Workspace::new("issuer", "session", WorkspaceLimits::default()).unwrap();
        let evidence = BTreeSet::from(["range:1".to_owned()]);
        let apply = apply_wire();
        let response = production_apply(&mut workspace, &apply, &evidence);
        let mut leaves = vec![leaf(&apply, &response, 0, 1, "mutation")];
        let inspect = json_value!({
            "operation":"inspect",
            "handle":response["result"]["handles"]["party"],
            "max_bytes":2048
        });
        let inspected = production_view(&mut workspace, &inspect);
        leaves.push(leaf(&inspect, &inspected, 1, 1, "view"));
        let state = workspace.capture_projection().unwrap();

        let mut tampered_response = inspected;
        tampered_response["result"]["rendered"] = Value::String("forged\n".into());
        leaves[1] = leaf(&inspect, &tampered_response, 1, 1, "view");
        assert!(reconstruct_workspace(&leaves, &BTreeMap::new(), &state, &evidence).is_err());

        let mut tampered_state = json(&state).unwrap();
        tampered_state["counters"]["aggregate_response_bytes"] = json_value!(0);
        assert!(reconstruct_workspace(
            &[leaf(&apply, &response, 0, 1, "mutation")],
            &BTreeMap::new(),
            &canonical(&tampered_state),
            &evidence
        )
        .is_err());
    }

    #[test]
    fn replays_recoverable_workspace_errors_then_success_with_exact_counters() {
        let mut workspace =
            Workspace::new("issuer", "session", WorkspaceLimits::default()).unwrap();
        let evidence = BTreeSet::from(["range:1".to_owned()]);
        let mut conflict = apply_wire();
        conflict["expected_revision"] = json_value!(1);
        conflict["idempotency_key"] = json_value!("stale-revision");
        let conflict_response = production_apply_error(&mut workspace, &conflict, &evidence);
        let missing = json_value!({"operation":"import", "handle":"g99~session"});
        let missing_response = production_import_error(&mut workspace, &missing);
        let apply = apply_wire();
        let applied = production_apply(&mut workspace, &apply, &evidence);
        let state = workspace.capture_projection().unwrap();
        let leaves = [
            leaf(&conflict, &conflict_response, 0, 0, "error"),
            leaf(&missing, &missing_response, 0, 0, "error"),
            leaf(&apply, &applied, 0, 1, "mutation"),
        ];
        reconstruct_workspace(&leaves, &BTreeMap::new(), &state, &evidence).unwrap();
        let state_json = json(&state).unwrap();
        assert_eq!(state_json["counters"]["tool_calls"], 3);
        assert_eq!(state_json["revision"], 1);

        let mut tampered = conflict_response.clone();
        tampered["code"] = json_value!("access_denied");
        let bad = [
            leaf(&conflict, &tampered, 0, 0, "error"),
            leaf(&missing, &missing_response, 0, 0, "error"),
            leaf(&apply, &applied, 0, 1, "mutation"),
        ];
        assert!(reconstruct_workspace(&bad, &BTreeMap::new(), &state, &evidence).is_err());

        let mut extra = conflict_response;
        extra["message"] = json_value!("private detail");
        let bad = [
            leaf(&conflict, &extra, 0, 0, "error"),
            leaf(&missing, &missing_response, 0, 0, "error"),
            leaf(&apply, &applied, 0, 1, "mutation"),
        ];
        assert!(reconstruct_workspace(&bad, &BTreeMap::new(), &state, &evidence).is_err());
    }

    #[test]
    fn replays_bounded_query_error_without_live_query_and_rejects_tampering() {
        let mut workspace =
            Workspace::new("issuer", "session", WorkspaceLimits::default()).unwrap();
        let request = json_value!({"query":"ABOUT entity:borrower"});
        let response = json_value!({
            "schema":"ctxql-graph-tool-error/v1",
            "status":"error",
            "code":"preparation_failed"
        });
        workspace
            .begin_call(request["query"].as_str().unwrap().len(), true)
            .unwrap();
        workspace
            .finish_call_bytes(serde_json::to_vec(&response).unwrap().len())
            .unwrap();
        let state = workspace.capture_projection().unwrap();
        let leaf = capability_leaf("graph_query", &request, &response, 0, 0, "error");
        reconstruct_workspace(&[leaf], &BTreeMap::new(), &state, &BTreeSet::new()).unwrap();

        let mut bad_response = response;
        bad_response["code"] = json_value!("not_a_public_code");
        let bad = capability_leaf("graph_query", &request, &bad_response, 0, 0, "error");
        assert!(reconstruct_workspace(&[bad], &BTreeMap::new(), &state, &BTreeSet::new()).is_err());
    }

    #[test]
    fn nondeterministic_playground_errors_and_unknown_versions_fail_closed() {
        let state = Workspace::new("issuer", "session", WorkspaceLimits::default())
            .unwrap()
            .capture_projection()
            .unwrap();
        let request = json_value!({"operation":"check"});
        let error = json_value!({
            "schema":"ctxql-graph-tool-error/v1",
            "status":"error",
            "code":"preparation_failed"
        });
        assert!(reconstruct_workspace(
            &[leaf(&request, &error, 0, 0, "error")],
            &BTreeMap::new(),
            &state,
            &BTreeSet::new()
        )
        .is_err());

        let mut future = json(&state).unwrap();
        future["schema"] = Value::String("ctxql-graph-workspace-state/v2".into());
        assert!(reconstruct_workspace(
            &[],
            &BTreeMap::new(),
            &canonical(&future),
            &BTreeSet::new()
        )
        .is_err());
    }
}
