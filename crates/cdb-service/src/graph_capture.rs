//! Immutable graph-tool interaction commitments. The bridge must persist each
//! leaf through `append_before_disclosure` before its response can be returned
//! to Pi. This module does not perform live graph queries or grant access.

mod reconstruction;
pub(crate) use reconstruction::reconstruct_workspace;

use crate::graph_context::{GraphContextLimits, GraphContextManifest};
use cdb_core::{id::ContentHash, CanonicalValue as V, Error, ErrorKind, Limits, Result};
use std::collections::BTreeSet;

pub(crate) const GRAPH_TRANSCRIPT_LEAF_SCHEMA: &str = "ctxql-graph-transcript-leaf/v1";
pub(crate) const GRAPH_CAPTURE_INDEX_SCHEMA_V1: &str = "ctxql-graph-capture-index/v1";
pub(crate) const GRAPH_CAPTURE_INDEX_SCHEMA_V2: &str = "ctxql-graph-capture-index/v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GraphCaptureLimits {
    pub max_leaves: usize,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_total_bytes: usize,
    pub max_dependencies: usize,
}

impl Default for GraphCaptureLimits {
    fn default() -> Self {
        Self {
            max_leaves: 40,
            max_request_bytes: 32 * 1024,
            max_response_bytes: 64 * 1024,
            max_total_bytes: 1024 * 1024,
            max_dependencies: 300,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphCapability {
    Query,
    Playground,
}
impl GraphCapability {
    fn as_str(self) -> &'static str {
        match self {
            Self::Query => "graph_query",
            Self::Playground => "graph_playground",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "graph_query" => Ok(Self::Query),
            "graph_playground" => Ok(Self::Playground),
            _ => Err(Error::invalid("graph transcript capability")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphResultKind {
    Graph,
    Diagnostic,
    View,
    Mutation,
    Check,
    Error,
}
impl GraphResultKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Graph => "graph",
            Self::Diagnostic => "diagnostic",
            Self::View => "view",
            Self::Mutation => "mutation",
            Self::Check => "check",
            Self::Error => "error",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "graph" => Ok(Self::Graph),
            "diagnostic" => Ok(Self::Diagnostic),
            "view" => Ok(Self::View),
            "mutation" => Ok(Self::Mutation),
            "check" => Ok(Self::Check),
            "error" => Ok(Self::Error),
            _ => Err(Error::invalid("graph transcript result kind")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GraphTranscriptLeaf {
    ordinal: u64,
    previous_leaf_root: Option<ContentHash>,
    capability: GraphCapability,
    request: Vec<u8>,
    response: Vec<u8>,
    revision_before: u64,
    revision_after: u64,
    result_kind: GraphResultKind,
    issued_handles: Vec<String>,
    graph_payload_root: Option<ContentHash>,
    dependencies: BTreeSet<String>,
}

impl GraphTranscriptLeaf {
    #[allow(clippy::too_many_arguments)]
    fn new(
        ordinal: u64,
        previous_leaf_root: Option<ContentHash>,
        capability: GraphCapability,
        request: Vec<u8>,
        response: Vec<u8>,
        revision_before: u64,
        revision_after: u64,
        result_kind: GraphResultKind,
        issued_handles: Vec<String>,
        graph_payload_root: Option<ContentHash>,
        dependencies: BTreeSet<String>,
        session_id: &str,
        limits: GraphCaptureLimits,
    ) -> Result<Self> {
        if request.len() > limits.max_request_bytes || response.len() > limits.max_response_bytes {
            return Err(Error::limit());
        }
        std::str::from_utf8(&request).map_err(|_| Error::invalid("graph request utf8"))?;
        std::str::from_utf8(&response).map_err(|_| Error::invalid("graph response utf8"))?;
        if revision_after < revision_before || dependencies.len() > limits.max_dependencies {
            return Err(Error::invalid("graph transcript revision or dependencies"));
        }
        let suffix = format!("~{session_id}");
        let mut unique = BTreeSet::new();
        for handle in &issued_handles {
            if handle.is_empty()
                || handle.len() > 2048
                || !handle.ends_with(&suffix)
                || !unique.insert(handle)
            {
                return Err(Error::invalid("graph transcript issued handle"));
            }
        }
        for dependency in &dependencies {
            cdb_core::id::ResourceId::new(dependency)?;
        }
        match result_kind {
            GraphResultKind::Graph => {
                if graph_payload_root.is_none()
                    || issued_handles.iter().all(|handle| !handle.starts_with('g'))
                {
                    return Err(Error::invalid("graph transcript graph result"));
                }
            }
            GraphResultKind::Diagnostic | GraphResultKind::Error => {
                if graph_payload_root.is_some() || !issued_handles.is_empty() {
                    return Err(Error::invalid("diagnostic published graph state"));
                }
                if revision_after != revision_before {
                    return Err(Error::invalid("diagnostic changed workspace revision"));
                }
            }
            _ if graph_payload_root.is_some() => {
                return Err(Error::invalid("non-query graph payload"));
            }
            _ => {}
        }
        Ok(Self {
            ordinal,
            previous_leaf_root,
            capability,
            request,
            response,
            revision_before,
            revision_after,
            result_kind,
            issued_handles,
            graph_payload_root,
            dependencies,
        })
    }

    pub(crate) fn projection(&self) -> Result<V> {
        let request =
            std::str::from_utf8(&self.request).map_err(|_| Error::invalid("graph request utf8"))?;
        let response = std::str::from_utf8(&self.response)
            .map_err(|_| Error::invalid("graph response utf8"))?;
        V::object([
            ("schema".into(), V::string(GRAPH_TRANSCRIPT_LEAF_SCHEMA)),
            ("ordinal".into(), V::integer(self.ordinal)),
            (
                "previous_leaf_root".into(),
                optional_hash(self.previous_leaf_root.as_ref()),
            ),
            ("capability".into(), V::string(self.capability.as_str())),
            ("request".into(), V::string(request)),
            (
                "request_root".into(),
                V::string(ContentHash::of_bytes(&self.request).as_str()),
            ),
            ("response".into(), V::string(response)),
            (
                "response_root".into(),
                V::string(ContentHash::of_bytes(&self.response).as_str()),
            ),
            ("revision_before".into(), V::integer(self.revision_before)),
            ("revision_after".into(), V::integer(self.revision_after)),
            ("result_kind".into(), V::string(self.result_kind.as_str())),
            (
                "issued_handles".into(),
                V::Array(self.issued_handles.iter().map(V::string).collect()),
            ),
            (
                "graph_payload_root".into(),
                optional_hash(self.graph_payload_root.as_ref()),
            ),
            (
                "claim_dependencies".into(),
                V::Array(self.dependencies.iter().map(V::string).collect()),
            ),
        ])
    }

    pub(crate) fn from_value(
        value: &V,
        session_id: &str,
        limits: GraphCaptureLimits,
    ) -> Result<Self> {
        value.closed(
            &[
                "schema",
                "ordinal",
                "previous_leaf_root",
                "capability",
                "request",
                "request_root",
                "response",
                "response_root",
                "revision_before",
                "revision_after",
                "result_kind",
                "issued_handles",
                "graph_payload_root",
                "claim_dependencies",
            ],
            &[],
        )?;
        if value.field("schema")?.as_str()? != GRAPH_TRANSCRIPT_LEAF_SCHEMA {
            return Err(Error::invalid("graph transcript leaf schema"));
        }
        let request = value.field("request")?.as_str()?.as_bytes().to_vec();
        let response = value.field("response")?.as_str()?.as_bytes().to_vec();
        if ContentHash::parse(value.field("request_root")?.as_str()?)?
            != ContentHash::of_bytes(&request)
            || ContentHash::parse(value.field("response_root")?.as_str()?)?
                != ContentHash::of_bytes(&response)
        {
            return Err(Error::invalid("graph transcript payload root"));
        }
        let leaf = Self::new(
            value.field("ordinal")?.u64()?,
            parse_optional_hash(value.field("previous_leaf_root")?)?,
            GraphCapability::parse(value.field("capability")?.as_str()?)?,
            request,
            response,
            value.field("revision_before")?.u64()?,
            value.field("revision_after")?.u64()?,
            GraphResultKind::parse(value.field("result_kind")?.as_str()?)?,
            value
                .field("issued_handles")?
                .as_array()?
                .iter()
                .map(|item| Ok(item.as_str()?.to_owned()))
                .collect::<Result<Vec<_>>>()?,
            parse_optional_hash(value.field("graph_payload_root")?)?,
            value
                .field("claim_dependencies")?
                .as_array()?
                .iter()
                .map(|item| Ok(item.as_str()?.to_owned()))
                .collect::<Result<BTreeSet<_>>>()?,
            session_id,
            limits,
        )?;
        if leaf.projection()? != *value {
            return Err(Error::invalid("graph transcript canonical image"));
        }
        Ok(leaf)
    }

    pub(crate) fn root(&self) -> Result<ContentHash> {
        Ok(ContentHash::of_bytes(
            &self.projection()?.canonical_bytes(Limits::default())?,
        ))
    }
}

pub(crate) trait GraphCaptureStore {
    fn persist_leaf(&self, root: &ContentHash, bytes: &[u8]) -> Result<()>;
}

/// The response is constructible only after the immutable sink accepted the
/// corresponding leaf. Callers may then expose exactly these bytes to Pi.
pub(crate) struct RecordedGraphResponse {
    bytes: Vec<u8>,
    leaf_root: ContentHash,
}
impl RecordedGraphResponse {
    pub(crate) fn model_visible_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn leaf_root(&self) -> &ContentHash {
        &self.leaf_root
    }
}

pub(crate) struct GraphCaptureRecorder {
    session_id: String,
    limits: GraphCaptureLimits,
    leaf_roots: Vec<ContentHash>,
    leaves: Vec<GraphTranscriptLeaf>,
    total_bytes: usize,
}
impl GraphCaptureRecorder {
    pub(crate) fn new(session_id: impl Into<String>, limits: GraphCaptureLimits) -> Result<Self> {
        let session_id = session_id.into();
        if session_id.is_empty() || session_id.len() > 2048 {
            return Err(Error::invalid("graph capture session"));
        }
        Ok(Self {
            session_id,
            limits,
            leaf_roots: Vec::new(),
            leaves: Vec::new(),
            total_bytes: 0,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn append_before_disclosure<S: GraphCaptureStore>(
        &mut self,
        sink: &S,
        capability: GraphCapability,
        request: Vec<u8>,
        response: Vec<u8>,
        revision_before: u64,
        revision_after: u64,
        result_kind: GraphResultKind,
        issued_handles: Vec<String>,
        graph_payload_root: Option<ContentHash>,
        dependencies: BTreeSet<String>,
    ) -> Result<RecordedGraphResponse> {
        if self.leaves.len() >= self.limits.max_leaves {
            return Err(Error::limit());
        }
        if self
            .leaves
            .last()
            .is_some_and(|previous| previous.revision_after != revision_before)
        {
            return Err(Error::new(
                ErrorKind::Conflict,
                "graph transcript revision discontinuity",
            ));
        }
        let ordinal = u64::try_from(self.leaves.len()).map_err(|_| Error::limit())?;
        let leaf = GraphTranscriptLeaf::new(
            ordinal,
            self.leaf_roots.last().cloned(),
            capability,
            request,
            response.clone(),
            revision_before,
            revision_after,
            result_kind,
            issued_handles,
            graph_payload_root,
            dependencies,
            &self.session_id,
            self.limits,
        )?;
        let bytes = leaf.projection()?.canonical_bytes(Limits::default())?;
        let total = self
            .total_bytes
            .checked_add(bytes.len())
            .ok_or_else(Error::limit)?;
        if total > self.limits.max_total_bytes {
            return Err(Error::limit());
        }
        let root = ContentHash::of_bytes(&bytes);
        // Persist before mutating recorder state or releasing response bytes.
        sink.persist_leaf(&root, &bytes)?;
        self.total_bytes = total;
        self.leaf_roots.push(root.clone());
        self.leaves.push(leaf);
        Ok(RecordedGraphResponse {
            bytes: response,
            leaf_root: root,
        })
    }

    pub(crate) fn previously_issued(&self, handle: &str) -> bool {
        self.leaves
            .iter()
            .any(|leaf| leaf.issued_handles.iter().any(|issued| issued == handle))
    }

    /// Retained query payloads count against the same cumulative capture cap,
    /// including after their live graph handles have been released.
    pub(crate) fn reserve_payload_bytes(&mut self, bytes: usize) -> Result<()> {
        let total = self
            .total_bytes
            .checked_add(bytes)
            .ok_or_else(Error::limit)?;
        if total > self.limits.max_total_bytes {
            return Err(Error::limit());
        }
        self.total_bytes = total;
        Ok(())
    }

    pub(crate) fn leaf_projections(&self) -> Result<Vec<V>> {
        self.leaves
            .iter()
            .map(GraphTranscriptLeaf::projection)
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finalize(
        &self,
        stable_session_seed: impl Into<String>,
        capability_summary_root: ContentHash,
        final_workspace_root: ContentHash,
        context: &GraphContextManifest,
    ) -> Result<GraphCaptureIndex> {
        let stable_session_seed = stable_session_seed.into();
        if stable_session_seed != self.session_id {
            return Err(Error::invalid("graph capture session seed"));
        }
        let graph_context_root = context.root()?;
        let dependencies = context.disclosed().clone();
        if dependencies.len() > self.limits.max_dependencies {
            return Err(Error::limit());
        }
        let final_revision = self
            .leaves
            .last()
            .map(|leaf| leaf.revision_after)
            .unwrap_or(0);
        GraphCaptureIndex::new(
            if context.gazetteer().is_some() {
                GRAPH_CAPTURE_INDEX_SCHEMA_V2
            } else {
                GRAPH_CAPTURE_INDEX_SCHEMA_V1
            },
            stable_session_seed,
            capability_summary_root,
            context.semantic_snapshot.clone(),
            context.source_version.clone(),
            context.source_range_root.clone(),
            self.leaf_roots.clone(),
            final_workspace_root,
            graph_context_root,
            final_revision,
            dependencies,
            self.limits,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GraphCaptureIndex {
    schema: &'static str,
    stable_session_seed: String,
    capability_summary_root: ContentHash,
    semantic_snapshot: String,
    source_version: String,
    source_range_root: String,
    leaf_roots: Vec<ContentHash>,
    transcript_root: ContentHash,
    final_workspace_root: ContentHash,
    graph_context_root: ContentHash,
    final_revision: u64,
    dependencies: BTreeSet<String>,
}
impl GraphCaptureIndex {
    #[allow(clippy::too_many_arguments)]
    fn new(
        schema: &'static str,
        stable_session_seed: String,
        capability_summary_root: ContentHash,
        semantic_snapshot: String,
        source_version: String,
        source_range_root: String,
        leaf_roots: Vec<ContentHash>,
        final_workspace_root: ContentHash,
        graph_context_root: ContentHash,
        final_revision: u64,
        dependencies: BTreeSet<String>,
        limits: GraphCaptureLimits,
    ) -> Result<Self> {
        if !matches!(
            schema,
            GRAPH_CAPTURE_INDEX_SCHEMA_V1 | GRAPH_CAPTURE_INDEX_SCHEMA_V2
        ) || stable_session_seed.is_empty()
            || stable_session_seed.len() > 2048
            || leaf_roots.len() > limits.max_leaves
            || dependencies.len() > limits.max_dependencies
        {
            return Err(Error::limit());
        }
        let transcript_root = root_list(&leaf_roots)?;
        Ok(Self {
            schema,
            stable_session_seed,
            capability_summary_root,
            semantic_snapshot,
            source_version,
            source_range_root,
            leaf_roots,
            transcript_root,
            final_workspace_root,
            graph_context_root,
            final_revision,
            dependencies,
        })
    }

    pub(crate) fn projection(&self) -> Result<V> {
        V::object([
            ("schema".into(), V::string(self.schema)),
            (
                "stable_session_seed".into(),
                V::string(&self.stable_session_seed),
            ),
            (
                "capability_summary_root".into(),
                V::string(self.capability_summary_root.as_str()),
            ),
            (
                "semantic_snapshot".into(),
                V::string(&self.semantic_snapshot),
            ),
            ("source_version".into(), V::string(&self.source_version)),
            (
                "source_range_root".into(),
                V::string(&self.source_range_root),
            ),
            (
                "leaf_roots".into(),
                V::Array(
                    self.leaf_roots
                        .iter()
                        .map(|root| V::string(root.as_str()))
                        .collect(),
                ),
            ),
            (
                "transcript_root".into(),
                V::string(self.transcript_root.as_str()),
            ),
            (
                "final_workspace_root".into(),
                V::string(self.final_workspace_root.as_str()),
            ),
            (
                "graph_context_root".into(),
                V::string(self.graph_context_root.as_str()),
            ),
            ("final_revision".into(), V::integer(self.final_revision)),
            (
                "claim_dependencies".into(),
                V::Array(self.dependencies.iter().map(V::string).collect()),
            ),
        ])
    }

    pub(crate) fn from_value(value: &V, limits: GraphCaptureLimits) -> Result<Self> {
        value.closed(
            &[
                "schema",
                "stable_session_seed",
                "capability_summary_root",
                "semantic_snapshot",
                "source_version",
                "source_range_root",
                "leaf_roots",
                "transcript_root",
                "final_workspace_root",
                "graph_context_root",
                "final_revision",
                "claim_dependencies",
            ],
            &[],
        )?;
        let schema = match value.field("schema")?.as_str()? {
            GRAPH_CAPTURE_INDEX_SCHEMA_V1 => GRAPH_CAPTURE_INDEX_SCHEMA_V1,
            GRAPH_CAPTURE_INDEX_SCHEMA_V2 => GRAPH_CAPTURE_INDEX_SCHEMA_V2,
            _ => return Err(Error::invalid("graph capture index schema")),
        };
        if value.canonical_bytes(Limits::default())?.len() > limits.max_total_bytes {
            return Err(Error::limit());
        }
        let index = Self::new(
            schema,
            value.field("stable_session_seed")?.as_str()?.to_owned(),
            ContentHash::parse(value.field("capability_summary_root")?.as_str()?)?,
            value.field("semantic_snapshot")?.as_str()?.to_owned(),
            value.field("source_version")?.as_str()?.to_owned(),
            value.field("source_range_root")?.as_str()?.to_owned(),
            value
                .field("leaf_roots")?
                .as_array()?
                .iter()
                .map(|root| ContentHash::parse(root.as_str()?))
                .collect::<Result<Vec<_>>>()?,
            ContentHash::parse(value.field("final_workspace_root")?.as_str()?)?,
            ContentHash::parse(value.field("graph_context_root")?.as_str()?)?,
            value.field("final_revision")?.u64()?,
            value
                .field("claim_dependencies")?
                .as_array()?
                .iter()
                .map(|item| Ok(item.as_str()?.to_owned()))
                .collect::<Result<BTreeSet<_>>>()?,
            limits,
        )?;
        if index.transcript_root != ContentHash::parse(value.field("transcript_root")?.as_str()?)?
            || index.projection()? != *value
        {
            return Err(Error::invalid("graph capture index root"));
        }
        Ok(index)
    }

    pub(crate) fn root(&self) -> Result<ContentHash> {
        Ok(ContentHash::of_bytes(
            &self.projection()?.canonical_bytes(Limits::default())?,
        ))
    }
}

pub(crate) struct VerifiedGraphCapture {
    pub final_revision: u64,
    pub issued_handles: BTreeSet<String>,
    pub dependencies: BTreeSet<String>,
    pub gazetteer_commitment: Option<String>,
    pub model_visible_responses: Vec<Vec<u8>>,
}

pub(crate) fn verify_graph_capture(
    index: &GraphCaptureIndex,
    leaf_values: &[V],
    context_value: &V,
    capability_summary_bytes: &[u8],
    final_workspace_value: &V,
    limits: GraphCaptureLimits,
) -> Result<VerifiedGraphCapture> {
    if leaf_values.len() != index.leaf_roots.len() {
        return Err(Error::invalid("graph capture leaf count"));
    }
    let context = GraphContextManifest::from_value(
        context_value,
        GraphContextLimits {
            max_graphs: 12,
            max_dependencies: limits.max_dependencies,
            max_bytes: limits.max_total_bytes,
        },
    )?;
    if context
        .gazetteer()
        .is_some_and(|value| value.snapshot.is_none())
    {
        return Err(Error::invalid("retained gazetteer snapshot missing"));
    }
    if context.root()? != index.graph_context_root
        || context.disclosed() != &index.dependencies
        || context.session_id != index.stable_session_seed
        || context.semantic_snapshot != index.semantic_snapshot
        || context.source_version != index.source_version
        || context.source_range_root != index.source_range_root
    {
        return Err(Error::new(
            ErrorKind::Denied,
            "graph capture context mismatch",
        ));
    }
    let mut previous_root = None;
    let mut previous_revision = None;
    if ContentHash::of_bytes(capability_summary_bytes) != index.capability_summary_root
        || ContentHash::of_bytes(&final_workspace_value.canonical_bytes(Limits::default())?)
            != index.final_workspace_root
    {
        return Err(Error::invalid("graph capture final commitment"));
    }
    let mut handles = BTreeSet::new();
    let mut responses = Vec::with_capacity(leaf_values.len());
    let mut disclosed = context.initial_dependencies();
    let mut total_bytes = 0usize;
    for (ordinal, (value, expected_root)) in leaf_values.iter().zip(&index.leaf_roots).enumerate() {
        let leaf_bytes = value.canonical_bytes(Limits::default())?;
        total_bytes = total_bytes
            .checked_add(leaf_bytes.len())
            .ok_or_else(Error::limit)?;
        if total_bytes > limits.max_total_bytes {
            return Err(Error::limit());
        }
        let leaf = GraphTranscriptLeaf::from_value(value, &index.stable_session_seed, limits)?;
        if leaf.ordinal != u64::try_from(ordinal).map_err(|_| Error::limit())?
            || leaf.previous_leaf_root != previous_root
            || previous_revision.is_some_and(|revision| revision != leaf.revision_before)
            || leaf.root()? != *expected_root
        {
            return Err(Error::invalid("graph capture sequence"));
        }
        for handle in &leaf.issued_handles {
            if !handles.insert(handle.clone()) {
                return Err(Error::invalid("graph capture duplicate handle"));
            }
        }
        disclosed.extend(leaf.dependencies.iter().cloned());
        validate_replayed_operation(&leaf)?;
        responses.push(leaf.response.clone());
        previous_revision = Some(leaf.revision_after);
        previous_root = Some(expected_root.clone());
    }
    if previous_revision.unwrap_or(0) != index.final_revision
        || root_list(&index.leaf_roots)? != index.transcript_root
        || disclosed != index.dependencies
        || (context.gazetteer().is_some()) != (index.schema == GRAPH_CAPTURE_INDEX_SCHEMA_V2)
    {
        return Err(Error::invalid("graph capture final state"));
    }
    final_workspace_value.closed(
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
        &[],
    )?;
    if final_workspace_value.field("schema")?.as_str()? != "ctxql-graph-workspace-state/v1"
        || final_workspace_value.field("session_id")?.as_str()? != index.stable_session_seed
        || final_workspace_value.field("revision")?.u64()? != index.final_revision
        || final_workspace_value
            .field("counters")?
            .field("tool_calls")?
            .u64()?
            != index.leaf_roots.len() as u64
    {
        return Err(Error::invalid("graph capture reconstructed state"));
    }
    Ok(VerifiedGraphCapture {
        final_revision: index.final_revision,
        issued_handles: handles,
        dependencies: index.dependencies.clone(),
        gazetteer_commitment: context.gazetteer().map(|value| value.commitment.clone()),
        model_visible_responses: responses,
    })
}

fn validate_replayed_operation(leaf: &GraphTranscriptLeaf) -> Result<()> {
    let request: serde_json::Value = serde_json::from_slice(&leaf.request)
        .map_err(|_| Error::invalid("graph replay request"))?;
    let response: serde_json::Value = serde_json::from_slice(&leaf.response)
        .map_err(|_| Error::invalid("graph replay response"))?;
    let delta = leaf.revision_after.saturating_sub(leaf.revision_before);
    match leaf.capability {
        GraphCapability::Query => {
            if delta != 0 {
                return Err(Error::invalid("graph query changed draft revision"));
            }
            match leaf.result_kind {
                GraphResultKind::Graph => {
                    let handle = response
                        .get("handle")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| Error::invalid("graph replay handle"))?;
                    if response.get("status").and_then(serde_json::Value::as_str) != Some("graph")
                        || response
                            .get("complete")
                            .and_then(serde_json::Value::as_bool)
                            != Some(true)
                        || !leaf.issued_handles.iter().any(|issued| issued == handle)
                        || leaf.graph_payload_root.is_none()
                    {
                        return Err(Error::invalid("graph replay result"));
                    }
                }
                GraphResultKind::Diagnostic | GraphResultKind::Error => {}
                _ => return Err(Error::invalid("graph replay query kind")),
            }
        }
        GraphCapability::Playground => {
            let operation = request
                .get("operation")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::invalid("graph replay operation"))?;
            let successful =
                response.get("status").and_then(serde_json::Value::as_str) == Some("ok");
            let expected_delta =
                successful && matches!(operation, "import" | "release_graph" | "apply");
            if (expected_delta && delta > 1) || (!expected_delta && delta != 0) {
                return Err(Error::invalid("graph replay revision"));
            }
            if operation == "apply" && successful {
                let revision = response
                    .get("result")
                    .and_then(|value| value.get("revision"))
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| Error::invalid("graph replay apply revision"))?;
                if revision != leaf.revision_after {
                    return Err(Error::invalid("graph replay apply revision"));
                }
            }
        }
    }
    Ok(())
}

fn optional_hash(value: Option<&ContentHash>) -> V {
    value
        .map(|hash| V::string(hash.as_str()))
        .unwrap_or(V::Null)
}
fn parse_optional_hash(value: &V) -> Result<Option<ContentHash>> {
    if *value == V::Null {
        Ok(None)
    } else {
        Ok(Some(ContentHash::parse(value.as_str()?)?))
    }
}
fn root_list(roots: &[ContentHash]) -> Result<ContentHash> {
    Ok(ContentHash::of_bytes(
        &V::Array(roots.iter().map(|root| V::string(root.as_str())).collect())
            .canonical_bytes(Limits::default())?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct MemorySink {
        writes: RefCell<Vec<(ContentHash, Vec<u8>)>>,
        fail: bool,
    }
    impl GraphCaptureStore for MemorySink {
        fn persist_leaf(&self, root: &ContentHash, bytes: &[u8]) -> Result<()> {
            if self.fail {
                return Err(Error::new(ErrorKind::Backend, "injected capture failure"));
            }
            self.writes
                .borrow_mut()
                .push((root.clone(), bytes.to_vec()));
            Ok(())
        }
    }

    fn context() -> GraphContextManifest {
        let mut context = GraphContextManifest::new(
            "issuer".into(),
            "session".into(),
            "attempt".into(),
            "sha256:source".into(),
            "sha256:ranges".into(),
            "semantic:1:cid".into(),
        );
        context
            .retain_graph("g1~session", BTreeSet::from(["urn:claim:a".into()]))
            .unwrap();
        context
    }

    #[test]
    fn persists_before_disclosure_and_verifies_offline() {
        let sink = MemorySink::default();
        let mut recorder =
            GraphCaptureRecorder::new("session", GraphCaptureLimits::default()).unwrap();
        let response = recorder
            .append_before_disclosure(
                &sink,
                GraphCapability::Query,
                br#"{"query":"narrow"}"#.to_vec(),
                br#"{"status":"graph","handle":"g1~session","complete":true}"#.to_vec(),
                0,
                0,
                GraphResultKind::Graph,
                vec!["g1~session".into()],
                Some(ContentHash::of_bytes(b"graph")),
                BTreeSet::from(["urn:claim:a".into()]),
            )
            .unwrap();
        assert_eq!(
            response.model_visible_bytes(),
            br#"{"status":"graph","handle":"g1~session","complete":true}"#
        );
        assert_eq!(sink.writes.borrow().len(), 1);
        assert_eq!(response.leaf_root(), &sink.writes.borrow()[0].0);
        let context = context();
        let final_workspace = V::object([
            ("schema".into(), V::string("ctxql-graph-workspace-state/v1")),
            ("issuer".into(), V::string("issuer")),
            ("session_id".into(), V::string("session")),
            ("revision".into(), V::integer(0)),
            ("limits".into(), V::object([]).unwrap()),
            ("graphs".into(), V::object([]).unwrap()),
            ("records".into(), V::object([]).unwrap()),
            ("idempotency".into(), V::object([]).unwrap()),
            (
                "counters".into(),
                V::object([("tool_calls".into(), V::integer(1))]).unwrap(),
            ),
            ("next".into(), V::object([]).unwrap()),
        ])
        .unwrap();
        let index = recorder
            .finalize(
                "session",
                ContentHash::of_bytes(b"capabilities"),
                ContentHash::of_bytes(&final_workspace.canonical_bytes(Limits::default()).unwrap()),
                &context,
            )
            .unwrap();
        let leaf_values = sink
            .writes
            .borrow()
            .iter()
            .map(|(_, bytes)| V::parse(bytes, Limits::default()).unwrap())
            .collect::<Vec<_>>();
        let verified = verify_graph_capture(
            &GraphCaptureIndex::from_value(
                &index.projection().unwrap(),
                GraphCaptureLimits::default(),
            )
            .unwrap(),
            &leaf_values,
            &context.projection().unwrap(),
            b"capabilities",
            &final_workspace,
            GraphCaptureLimits::default(),
        )
        .unwrap();
        assert_eq!(verified.final_revision, 0);
        assert!(verified.issued_handles.contains("g1~session"));
        assert_eq!(
            verified.dependencies,
            BTreeSet::from(["urn:claim:a".into()])
        );
        assert_eq!(verified.model_visible_responses.len(), 1);
    }

    #[test]
    fn failed_persistence_releases_no_response_or_state() {
        let sink = MemorySink {
            fail: true,
            ..MemorySink::default()
        };
        let mut recorder =
            GraphCaptureRecorder::new("session", GraphCaptureLimits::default()).unwrap();
        assert!(recorder
            .append_before_disclosure(
                &sink,
                GraphCapability::Query,
                b"{}".to_vec(),
                b"error".to_vec(),
                0,
                0,
                GraphResultKind::Error,
                vec![],
                None,
                BTreeSet::new(),
            )
            .is_err());
        assert!(recorder.leaves.is_empty());
    }

    #[test]
    fn sequence_and_index_tampering_fail_closed() {
        let sink = MemorySink::default();
        let limits = GraphCaptureLimits::default();
        let mut recorder = GraphCaptureRecorder::new("session", limits).unwrap();
        recorder
            .append_before_disclosure(
                &sink,
                GraphCapability::Playground,
                b"apply".to_vec(),
                b"applied".to_vec(),
                0,
                1,
                GraphResultKind::Mutation,
                vec!["n1~session".into()],
                None,
                BTreeSet::from(["urn:claim:a".into()]),
            )
            .unwrap();
        assert!(recorder
            .append_before_disclosure(
                &sink,
                GraphCapability::Playground,
                b"view".to_vec(),
                b"viewed".to_vec(),
                0,
                0,
                GraphResultKind::View,
                vec![],
                None,
                BTreeSet::new(),
            )
            .is_err());
        assert_eq!(sink.writes.borrow().len(), 1);

        let context = context();
        let workspace = V::object([("revision".into(), V::integer(1))]).unwrap();
        let index = recorder
            .finalize(
                "session",
                ContentHash::of_bytes(b"capabilities"),
                ContentHash::of_bytes(&workspace.canonical_bytes(Limits::default()).unwrap()),
                &context,
            )
            .unwrap();
        let mut forged = index.projection().unwrap();
        let V::Object(fields) = &mut forged else {
            unreachable!()
        };
        fields.insert(
            "transcript_root".into(),
            V::string(ContentHash::of_bytes(b"forged").as_str()),
        );
        assert!(GraphCaptureIndex::from_value(&forged, limits).is_err());
        assert!(verify_graph_capture(
            &index,
            &[],
            &context.projection().unwrap(),
            b"capabilities",
            &workspace,
            limits,
        )
        .is_err());
    }

    #[test]
    fn diagnostic_cannot_invent_graph_and_tampering_is_detected() {
        let limits = GraphCaptureLimits::default();
        assert!(GraphTranscriptLeaf::new(
            0,
            None,
            GraphCapability::Query,
            b"{}".to_vec(),
            b"too broad".to_vec(),
            0,
            0,
            GraphResultKind::Diagnostic,
            vec!["g1~session".into()],
            Some(ContentHash::of_bytes(b"graph")),
            BTreeSet::new(),
            "session",
            limits,
        )
        .is_err());

        let leaf = GraphTranscriptLeaf::new(
            0,
            None,
            GraphCapability::Playground,
            b"{}".to_vec(),
            b"ok".to_vec(),
            0,
            1,
            GraphResultKind::Mutation,
            vec!["n1~session".into()],
            None,
            BTreeSet::new(),
            "session",
            limits,
        )
        .unwrap();
        let mut value = leaf.projection().unwrap();
        let V::Object(fields) = &mut value else {
            unreachable!()
        };
        fields.insert("response".into(), V::string("forged"));
        assert!(GraphTranscriptLeaf::from_value(&value, "session", limits).is_err());
    }
}
