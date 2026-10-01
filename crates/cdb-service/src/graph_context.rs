//! Host-owned, append-only authority dependencies for one document session.
//! The durable projection deliberately excludes socket tokens and wall clocks.

use cdb_core::{
    id::{ContentHash, ResourceId},
    CanonicalValue as V, Error, Limits, Result,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const GRAPH_CONTEXT_SCHEMA_V1: &str = "ctxql-graph-context/v1";
pub(crate) const GRAPH_CONTEXT_SCHEMA_V2: &str = "ctxql-graph-context/v2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct GazetteerContext {
    pub commitment: String,
    pub dependencies: BTreeSet<String>,
    pub snapshot: Option<String>,
}

impl GazetteerContext {
    pub(crate) fn new(commitment: String, dependencies: BTreeSet<String>) -> Result<Self> {
        validate_identifier("gazetteer commitment", &commitment)?;
        ContentHash::parse(&commitment)?;
        for dependency in &dependencies {
            validate_dependency(dependency)?;
        }
        Ok(Self {
            commitment,
            dependencies,
            snapshot: None,
        })
    }

    fn projection(&self) -> Result<V> {
        V::object([
            ("kind".into(), V::string("entity_gazetteer")),
            ("commitment".into(), V::string(&self.commitment)),
            (
                "snapshot".into(),
                self.snapshot.as_ref().map(V::string).unwrap_or(V::Null),
            ),
            (
                "claim_ids".into(),
                V::Array(self.dependencies.iter().map(V::string).collect()),
            ),
        ])
    }

    fn from_value(value: &V) -> Result<Self> {
        value.closed(&["kind", "commitment", "claim_ids", "snapshot"], &[])?;
        if value.field("kind")?.as_str()? != "entity_gazetteer" {
            return Err(Error::invalid("initial graph context kind"));
        }
        let dependencies = value
            .field("claim_ids")?
            .as_array()?
            .iter()
            .map(|item| Ok(item.as_str()?.to_owned()))
            .collect::<Result<BTreeSet<_>>>()?;
        let mut context = Self::new(
            value.field("commitment")?.as_str()?.to_owned(),
            dependencies,
        )?;
        context.snapshot = match value.field("snapshot")? {
            V::Null => None,
            value => Some(value.as_str()?.to_owned()),
        };
        if let Some(snapshot) = &context.snapshot {
            let retained = V::parse(snapshot.as_bytes(), Limits::default())?;
            retained.closed(
                &[
                    "schema",
                    "entities",
                    "approved",
                    "approval_root",
                    "class_supports",
                    "commitment",
                    "dependencies",
                ],
                &[],
            )?;
            if retained.field("schema")?.as_str()? != "ctxql-retained-gazetteer/v1"
                || retained.field("commitment")?.as_str()? != context.commitment
                || retained.field("dependencies")?
                    != &V::Array(context.dependencies.iter().map(V::string).collect())
            {
                return Err(Error::invalid("gazetteer snapshot binding"));
            }
        }
        if context.projection()? != *value {
            return Err(Error::invalid("gazetteer context canonical image"));
        }
        Ok(context)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct GraphContextLimits {
    pub max_graphs: usize,
    pub max_dependencies: usize,
    pub max_bytes: usize,
}

impl Default for GraphContextLimits {
    fn default() -> Self {
        Self {
            // Released graphs remain in disclosed-context history; live slots
            // are bounded separately by Workspace.
            max_graphs: 12,
            max_dependencies: 300,
            max_bytes: 2 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct GraphContextManifest {
    pub issuer: String,
    pub session_id: String,
    pub attempt_id: String,
    pub source_version: String,
    pub source_range_root: String,
    pub semantic_snapshot: String,
    gazetteer: Option<GazetteerContext>,
    disclosed: BTreeSet<String>,
    graph_dependencies: BTreeMap<String, BTreeSet<String>>,
}

impl GraphContextManifest {
    pub(crate) fn new(
        issuer: String,
        session_id: String,
        attempt_id: String,
        source_version: String,
        source_range_root: String,
        semantic_snapshot: String,
    ) -> Self {
        Self {
            issuer,
            session_id,
            attempt_id,
            source_version,
            source_range_root,
            semantic_snapshot,
            gazetteer: None,
            disclosed: BTreeSet::new(),
            graph_dependencies: BTreeMap::new(),
        }
    }

    pub(crate) fn retain_gazetteer(&mut self, gazetteer: GazetteerContext) -> Result<()> {
        if self.gazetteer.is_some() || !self.graph_dependencies.is_empty() {
            return Err(Error::new(
                cdb_core::ErrorKind::Conflict,
                "initial context must precede graph disclosure",
            ));
        }
        let limits = GraphContextLimits::default();
        if gazetteer.dependencies.len() > limits.max_dependencies {
            return Err(Error::limit());
        }
        let mut disclosed = self.disclosed.clone();
        disclosed.extend(gazetteer.dependencies.iter().cloned());
        let previous = self.gazetteer.replace(gazetteer);
        let previous_disclosed = std::mem::replace(&mut self.disclosed, disclosed);
        if self.retained_bytes()? > limits.max_bytes {
            self.gazetteer = previous;
            self.disclosed = previous_disclosed;
            return Err(Error::limit());
        }
        Ok(())
    }

    pub(crate) fn gazetteer(&self) -> Option<&GazetteerContext> {
        self.gazetteer.as_ref()
    }

    pub(crate) fn initial_dependencies(&self) -> BTreeSet<String> {
        self.gazetteer
            .as_ref()
            .map(|value| value.dependencies.clone())
            .unwrap_or_default()
    }

    pub(crate) fn retain_graph(
        &mut self,
        handle: &str,
        dependencies: BTreeSet<String>,
    ) -> Result<()> {
        if self.graph_dependencies.contains_key(handle) {
            return Err(Error::new(
                cdb_core::ErrorKind::Conflict,
                "graph dependency handle reused",
            ));
        }
        validate_identifier("graph handle", handle)?;
        for dependency in &dependencies {
            validate_dependency(dependency)?;
        }
        let limits = GraphContextLimits::default();
        if self.graph_dependencies.len() >= limits.max_graphs
            || self.disclosed.union(&dependencies).count() > limits.max_dependencies
        {
            return Err(Error::limit());
        }
        self.disclosed.extend(dependencies.iter().cloned());
        self.graph_dependencies
            .insert(handle.to_owned(), dependencies);
        Ok(())
    }

    pub(crate) fn disclosed(&self) -> &BTreeSet<String> {
        &self.disclosed
    }

    pub(crate) fn graph_dependencies(&self, handle: &str) -> Option<&BTreeSet<String>> {
        self.graph_dependencies.get(handle)
    }

    pub(crate) fn projection(&self) -> Result<V> {
        validate_identifier("issuer", &self.issuer)?;
        validate_identifier("session id", &self.session_id)?;
        validate_identifier("attempt id", &self.attempt_id)?;
        validate_identifier("source version", &self.source_version)?;
        validate_identifier("source range root", &self.source_range_root)?;
        validate_identifier("semantic snapshot", &self.semantic_snapshot)?;
        let graph_dependencies = self
            .graph_dependencies
            .iter()
            .map(|(handle, dependencies)| {
                V::object([
                    ("graph_handle".into(), V::string(handle)),
                    (
                        "claim_ids".into(),
                        V::Array(dependencies.iter().map(V::string).collect()),
                    ),
                ])
            })
            .collect::<Result<Vec<_>>>()?;
        let schema = if self.gazetteer.is_some() {
            GRAPH_CONTEXT_SCHEMA_V2
        } else {
            GRAPH_CONTEXT_SCHEMA_V1
        };
        let mut fields = BTreeMap::from([
            ("schema".into(), V::string(schema)),
            ("issuer".into(), V::string(&self.issuer)),
            ("session_id".into(), V::string(&self.session_id)),
            ("attempt_id".into(), V::string(&self.attempt_id)),
            ("source_version".into(), V::string(&self.source_version)),
            (
                "source_range_root".into(),
                V::string(&self.source_range_root),
            ),
            (
                "semantic_snapshot".into(),
                V::string(&self.semantic_snapshot),
            ),
            (
                "disclosed_claim_ids".into(),
                V::Array(self.disclosed.iter().map(V::string).collect()),
            ),
            ("graphs".into(), V::Array(graph_dependencies)),
        ]);
        if let Some(gazetteer) = &self.gazetteer {
            fields.insert(
                "initial_context".into(),
                V::Array(vec![gazetteer.projection()?]),
            );
        }
        Ok(V::Object(fields))
    }

    pub(crate) fn from_value(value: &V, limits: GraphContextLimits) -> Result<Self> {
        let schema = value.field("schema")?.as_str()?;
        let gazetteer = match schema {
            GRAPH_CONTEXT_SCHEMA_V1 => {
                value.closed(
                    &[
                        "schema",
                        "issuer",
                        "session_id",
                        "attempt_id",
                        "source_version",
                        "source_range_root",
                        "semantic_snapshot",
                        "disclosed_claim_ids",
                        "graphs",
                    ],
                    &[],
                )?;
                None
            }
            GRAPH_CONTEXT_SCHEMA_V2 => {
                value.closed(
                    &[
                        "schema",
                        "issuer",
                        "session_id",
                        "attempt_id",
                        "source_version",
                        "source_range_root",
                        "semantic_snapshot",
                        "initial_context",
                        "disclosed_claim_ids",
                        "graphs",
                    ],
                    &[],
                )?;
                let initial = value.field("initial_context")?.as_array()?;
                if initial.len() != 1 {
                    return Err(Error::invalid("initial graph context"));
                }
                Some(GazetteerContext::from_value(&initial[0])?)
            }
            _ => return Err(Error::invalid("graph context schema")),
        };
        let bytes = value.canonical_bytes(Limits::default())?;
        if bytes.len() > limits.max_bytes {
            return Err(Error::limit());
        }
        let mut graph_dependencies = BTreeMap::new();
        let graphs = value.field("graphs")?.as_array()?;
        if graphs.len() > limits.max_graphs {
            return Err(Error::limit());
        }
        let mut union = BTreeSet::new();
        for graph in graphs {
            graph.closed(&["graph_handle", "claim_ids"], &[])?;
            let handle = graph.field("graph_handle")?.as_str()?.to_owned();
            validate_identifier("graph handle", &handle)?;
            let mut dependencies = BTreeSet::new();
            for dependency in graph.field("claim_ids")?.as_array()? {
                let dependency = dependency.as_str()?.to_owned();
                validate_dependency(&dependency)?;
                if !dependencies.insert(dependency) {
                    return Err(Error::invalid("duplicate graph dependency"));
                }
            }
            if graph_dependencies
                .insert(handle, dependencies.clone())
                .is_some()
            {
                return Err(Error::invalid("duplicate graph dependency handle"));
            }
            union.extend(dependencies);
        }
        if let Some(gazetteer) = &gazetteer {
            union.extend(gazetteer.dependencies.iter().cloned());
        }
        if union.len() > limits.max_dependencies {
            return Err(Error::limit());
        }
        let disclosed = value
            .field("disclosed_claim_ids")?
            .as_array()?
            .iter()
            .map(|item| {
                let id = item.as_str()?.to_owned();
                validate_dependency(&id)?;
                Ok(id)
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if disclosed != union {
            return Err(Error::invalid("graph context dependency union"));
        }
        let manifest = Self {
            issuer: value.field("issuer")?.as_str()?.to_owned(),
            session_id: value.field("session_id")?.as_str()?.to_owned(),
            attempt_id: value.field("attempt_id")?.as_str()?.to_owned(),
            source_version: value.field("source_version")?.as_str()?.to_owned(),
            source_range_root: value.field("source_range_root")?.as_str()?.to_owned(),
            semantic_snapshot: value.field("semantic_snapshot")?.as_str()?.to_owned(),
            gazetteer,
            disclosed,
            graph_dependencies,
        };
        // Re-project to enforce identifier validation and a single canonical image.
        if manifest.projection()? != *value {
            return Err(Error::invalid("graph context canonical image"));
        }
        Ok(manifest)
    }

    pub(crate) fn root(&self) -> Result<ContentHash> {
        Ok(ContentHash::of_bytes(
            &self.projection()?.canonical_bytes(Limits::default())?,
        ))
    }

    pub(crate) fn retained_bytes(&self) -> Result<usize> {
        Ok(self.projection()?.canonical_bytes(Limits::default())?.len())
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
        return Err(Error::invalid(field));
    }
    Ok(())
}

fn validate_dependency(value: &str) -> Result<()> {
    validate_identifier("graph dependency", value)?;
    ResourceId::new(value)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            .retain_graph(
                "g1~session",
                BTreeSet::from(["urn:claim:a".into(), "urn:claim:b".into()]),
            )
            .unwrap();
        context
    }

    #[test]
    fn durable_context_round_trips_and_binds_union() {
        let context = context();
        let value = context.projection().unwrap();
        let decoded =
            GraphContextManifest::from_value(&value, GraphContextLimits::default()).unwrap();
        assert_eq!(decoded, context);
        assert_eq!(decoded.root().unwrap(), context.root().unwrap());

        let mut forged = value;
        let V::Object(fields) = &mut forged else {
            unreachable!()
        };
        fields.insert(
            "disclosed_claim_ids".into(),
            V::Array(vec![V::string("urn:claim:a")]),
        );
        assert!(GraphContextManifest::from_value(&forged, GraphContextLimits::default()).is_err());
    }

    #[test]
    fn v2_retains_initial_gazetteer_separately_from_query_graphs() {
        let mut context = GraphContextManifest::new(
            "issuer".into(),
            "session".into(),
            "attempt".into(),
            "sha256:source".into(),
            "sha256:ranges".into(),
            "semantic:1:cid".into(),
        );
        context
            .retain_gazetteer(
                GazetteerContext::new(
                    ContentHash::of_bytes(b"gazetteer").as_str().to_owned(),
                    BTreeSet::from(["urn:claim:identity".into()]),
                )
                .unwrap(),
            )
            .unwrap();
        let value = context.projection().unwrap();
        assert_eq!(
            value.field("schema").unwrap().as_str().unwrap(),
            GRAPH_CONTEXT_SCHEMA_V2
        );
        assert!(value
            .field("graphs")
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
        let decoded =
            GraphContextManifest::from_value(&value, GraphContextLimits::default()).unwrap();
        assert_eq!(decoded, context);
        assert_eq!(
            decoded.initial_dependencies(),
            BTreeSet::from(["urn:claim:identity".into()])
        );

        let mut historical = value;
        let V::Object(fields) = &mut historical else {
            unreachable!()
        };
        fields.insert("schema".into(), V::string(GRAPH_CONTEXT_SCHEMA_V1));
        fields.remove("initial_context");
        fields.insert("disclosed_claim_ids".into(), V::Array(Vec::new()));
        fields.insert("graphs".into(), V::Array(Vec::new()));
        assert!(
            GraphContextManifest::from_value(&historical, GraphContextLimits::default()).is_ok()
        );
    }

    #[test]
    fn durable_context_enforces_graph_dependency_and_byte_limits() {
        let value = context().projection().unwrap();
        assert!(GraphContextManifest::from_value(
            &value,
            GraphContextLimits {
                max_graphs: 0,
                ..GraphContextLimits::default()
            }
        )
        .is_err());
        assert!(GraphContextManifest::from_value(
            &value,
            GraphContextLimits {
                max_dependencies: 1,
                ..GraphContextLimits::default()
            }
        )
        .is_err());
        assert!(GraphContextManifest::from_value(
            &value,
            GraphContextLimits {
                max_bytes: 1,
                ..GraphContextLimits::default()
            }
        )
        .is_err());
    }
}
