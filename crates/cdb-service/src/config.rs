//! Strict node-local configuration and trusted-path private file helpers.
mod chat;
pub use chat::{ChatConfig, ChatLimits, ChatOntologyConfig};

use crate::{
    auth::{AuthStore, Capabilities, CredentialRecord, Operation},
    broker::startup::{self, AdapterCatalog, BrokerConfig, StartupBundle, StartupError},
};
use cdb_backend_fluree::{AuthorityOptions, SemanticLedgerOptions};
use cdb_core::{
    artifact::ArtifactRef,
    id::{AuthorityId, BackendId, ContentHash, GraphId, Iri, PrincipalId, VersionId},
    Timestamp,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

const FILE_CAP: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    Invalid,
    Io,
    Unsupported,
    Limit,
    UnsafePath,
}
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid local configuration",
            Self::Io => "local file operation failed",
            Self::Unsupported => "private file access unsupported",
            Self::Limit => "local file limit exceeded",
            Self::UnsafePath => "unsafe local path",
        })
    }
}
impl std::error::Error for ConfigError {}
impl From<ConfigError> for cdb_core::Error {
    fn from(error: ConfigError) -> Self {
        use cdb_core::ErrorKind;
        let kind = match error {
            ConfigError::Invalid => ErrorKind::Invalid,
            ConfigError::Io => ErrorKind::Backend,
            ConfigError::Unsupported => ErrorKind::Unsupported,
            ConfigError::Limit => ErrorKind::Limit,
            ConfigError::UnsafePath => ErrorKind::Denied,
        };
        Self::new(kind, "local configuration or file operation failed")
    }
}
type Result<T> = std::result::Result<T, ConfigError>;
fn invalid<T, E>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|_| ConfigError::Invalid)
}
#[derive(Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InstanceRole {
    Dev,
    #[default]
    Replayable,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfig {
    pub path: PathBuf,
    pub ledger: String,
    pub backend: String,
    pub authority: String,
    pub graph: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReference {
    pub iri: String,
    pub version: String,
    pub hash: String,
}
impl ArtifactReference {
    pub fn artifact_ref(&self) -> Result<ArtifactRef> {
        Ok(ArtifactRef::new(
            invalid(Iri::new(&self.iri))?,
            invalid(VersionId::new(&self.version))?,
            invalid(ContentHash::parse(&self.hash))?,
        ))
    }
}
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServiceLimits {
    pub max_body_bytes: usize,
    pub concurrency: usize,
    pub connections: usize,
    pub deadline_seconds: usize,
    pub run_bytes: usize,
    pub trace_entries: usize,
    pub max_work: usize,
    pub session_ttl_seconds: usize,
}
impl Default for ServiceLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: FILE_CAP,
            concurrency: 8,
            connections: 32,
            deadline_seconds: 30,
            run_bytes: FILE_CAP,
            trace_entries: 10_000,
            max_work: 1_000_000,
            session_ttl_seconds: 300,
        }
    }
}
impl ServiceLimits {
    pub fn validate(&self) -> Result<()> {
        self.validate_with_lifetime_cap(300)
    }
    fn validate_with_lifetime_cap(&self, lifetime_cap: usize) -> Result<()> {
        for (n, cap) in [
            (self.max_body_bytes, 16 * FILE_CAP),
            (self.concurrency, 256),
            (self.connections, 1024),
            (self.deadline_seconds, lifetime_cap),
            (self.run_bytes, 16 * FILE_CAP),
            (self.trace_entries, 100_000),
            (self.session_ttl_seconds, lifetime_cap),
        ] {
            if n == 0 || n > cap {
                return Err(ConfigError::Limit);
            }
        }
        // Zero is an intentional rejecting execution budget, not an invalid cap.
        if self.max_work > 100_000_000 {
            return Err(ConfigError::Limit);
        }
        Ok(())
    }
    pub fn deadline(&self) -> Duration {
        Duration::from_secs(self.deadline_seconds as u64)
    }
    pub fn session_ttl(&self) -> Duration {
        Duration::from_secs(self.session_ttl_seconds as u64)
    }
}
fn default_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AcquisitionAccessMode {
    Direct,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AcquisitionProtocol {
    LegacyV1,
    OntologyV2,
}

fn default_acquisition_protocol() -> AcquisitionProtocol {
    AcquisitionProtocol::LegacyV1
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AcquisitionAssertionPolicy {
    Accepted,
    EvidenceOnly,
}

fn default_assertion_policy() -> AcquisitionAssertionPolicy {
    AcquisitionAssertionPolicy::Accepted
}

impl AcquisitionAssertionPolicy {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "accepted" => Ok(Self::Accepted),
            "evidence-only" => Ok(Self::EvidenceOnly),
            _ => Err(ConfigError::Invalid),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AcquisitionWindowConfig {
    pub mode: String,
    pub target_bytes: usize,
    pub max_bytes: usize,
    pub overlap_bytes: usize,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AcquisitionConverterConfig {
    pub command: PathBuf,
    pub version: String,
    pub executable_hash: String,
    #[serde(default)]
    pub arguments: Vec<String>,
    pub normalization: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AcquisitionUrlAdapterConfig {
    pub base_url: String,
    pub max_bytes: usize,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AcquisitionGraphWorkspaceConfig {
    #[serde(default)]
    pub query_config: Option<ArtifactReference>,
    #[serde(default)]
    pub profile_selector: Option<String>,
    #[serde(default)]
    pub profile: Option<ArtifactReference>,
    pub query_timeout_seconds: usize,
    pub max_nodes: usize,
    pub max_claims: usize,
    pub max_live_graphs: usize,
    pub max_tool_calls: usize,
    pub max_graph_queries: usize,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_aggregate_bytes: usize,
    pub max_state_bytes: usize,
    pub max_context_bytes: usize,
    pub reserved_final_output_bytes: usize,
    pub reserved_tool_result_bytes: usize,
}

impl AcquisitionGraphWorkspaceConfig {
    fn validate_shape(&self, provider_timeout_seconds: usize) -> Result<()> {
        if self.query_timeout_seconds == 0
            || self.query_timeout_seconds > provider_timeout_seconds
            || self.max_nodes == 0
            || self.max_nodes > 50
            || self.max_claims == 0
            || self.max_claims > 100
            || self.max_live_graphs == 0
            || self.max_live_graphs > 3
            || self.max_tool_calls == 0
            || self.max_tool_calls > 40
            || self.max_graph_queries == 0
            || self.max_graph_queries > 12
            || self.max_graph_queries > self.max_tool_calls
            || self.max_request_bytes == 0
            || self.max_request_bytes > 32 * 1024
            || self.max_response_bytes == 0
            || self.max_response_bytes > 64 * 1024
            || self.max_aggregate_bytes == 0
            || self.max_aggregate_bytes > 1024 * 1024
            || self.max_state_bytes == 0
            || self.max_state_bytes > 2 * 1024 * 1024
            || self.max_context_bytes == 0
            || self.max_context_bytes > 512 * 1024
            || self.reserved_final_output_bytes == 0
            || self.reserved_tool_result_bytes == 0
            || self.reserved_tool_result_bytes > self.max_aggregate_bytes
            || self
                .reserved_final_output_bytes
                .checked_add(self.reserved_tool_result_bytes)
                .is_none_or(|reserved| reserved > self.max_context_bytes)
            || self.max_request_bytes > self.max_context_bytes
            || self.profile_selector.is_some() != self.profile.is_some()
            || self
                .profile_selector
                .as_ref()
                .is_some_and(|selector| selector.is_empty() || selector.len() > 512)
        {
            return Err(ConfigError::Invalid);
        }
        if let Some(reference) = &self.query_config {
            reference.artifact_ref()?;
        }
        if let Some(reference) = &self.profile {
            reference.artifact_ref()?;
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AcquisitionConfig {
    pub access_mode: AcquisitionAccessMode,
    #[serde(default = "default_acquisition_protocol")]
    pub protocol: AcquisitionProtocol,
    #[serde(default = "default_assertion_policy")]
    pub assertions: AcquisitionAssertionPolicy,
    #[serde(default)]
    pub review_graph: Option<String>,
    #[serde(default)]
    pub approved_entity_iris: Vec<String>,
    #[serde(default)]
    pub entity_source: Option<AcquisitionEntitySource>,
    #[serde(default)]
    pub ontology_briefing: Option<crate::ontology_briefing::OntologyBriefingSeedManifest>,
    pub claims_graph: String,
    pub principal: String,
    pub action: String,
    pub pi_command: PathBuf,
    pub pi_bundle: PathBuf,
    /// Explicit opt-in destination for sensitive native Pi sessions and
    /// content-free host diagnostics. Absent means no local session logging.
    #[serde(default)]
    pub pi_session_log_dir: Option<PathBuf>,
    #[serde(rename = "extractor_model")]
    pub extractor_model: String,
    pub thinking: String,
    pub batch_size: usize,
    pub max_source_bytes: usize,
    pub max_document_bytes: usize,
    pub max_folder_entries: usize,
    pub provider_timeout_seconds: usize,
    pub projection_timeout_seconds: usize,
    pub control_journal_bytes: usize,
    pub ontology_profile: String,
    pub ontology_catalog_root: String,
    #[serde(default)]
    pub ontology_ledger_path: Option<PathBuf>,
    pub window: AcquisitionWindowConfig,
    #[serde(default)]
    pub graph_workspace: Option<AcquisitionGraphWorkspaceConfig>,
    #[serde(default)]
    pub allowed_local_roots: Vec<PathBuf>,
    #[serde(default)]
    pub converters: BTreeMap<String, AcquisitionConverterConfig>,
    #[serde(default)]
    pub url_adapters: BTreeMap<String, AcquisitionUrlAdapterConfig>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AcquisitionEntitySource {
    pub graphs: Vec<String>,
    #[serde(default)]
    pub classes: Vec<String>,
    pub identifying_predicates: Vec<String>,
}

impl AcquisitionConfig {
    fn validate_shape(&self) -> Result<()> {
        if self.extractor_model != cdb_provider_pi::MODEL
            || self.thinking != cdb_provider_pi::THINKING
            || self.batch_size != 2
            || self.max_source_bytes == 0
            || self.max_source_bytes > 128 * 1024 * 1024
            || self.max_document_bytes == 0
            || self.max_document_bytes > self.max_source_bytes
            || self.max_document_bytes > 32 * 1024 * 1024
            || !(1..=4096).contains(&self.max_folder_entries)
            || !(1..=300).contains(&self.provider_timeout_seconds)
            || !(1..=300).contains(&self.projection_timeout_seconds)
            || !(1..=64 * 1024 * 1024).contains(&self.control_journal_bytes)
            || (self.protocol == AcquisitionProtocol::OntologyV2
                && self.ontology_profile != cdb_core::recording_v5::CURRENT_ACQUISITION_PROFILE_ID)
            || (self.protocol == AcquisitionProtocol::LegacyV1
                && self.ontology_profile
                    != cdb_core::recording_v4::ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID)
            || !matches!(self.window.mode.as_str(), "off" | "auto" | "always")
            || self.window.target_bytes == 0
            || self.window.max_bytes < self.window.target_bytes
            || self.window.max_bytes > self.max_document_bytes
            || self.window.overlap_bytes >= self.window.max_bytes
            || self.allowed_local_roots.is_empty()
            || self.allowed_local_roots.len() > 64
            || self.converters.len() > 32
            || self.url_adapters.len() > 32
        {
            return Err(ConfigError::Invalid);
        }
        invalid(Iri::new(&self.claims_graph))?;
        if self.protocol == AcquisitionProtocol::OntologyV2 {
            let review_graph = self.review_graph.as_deref().ok_or(ConfigError::Invalid)?;
            invalid(Iri::new(review_graph))?;
            if review_graph == self.claims_graph {
                return Err(ConfigError::Invalid);
            }
        }
        if let Some(graph) = &self.graph_workspace {
            if self.protocol != AcquisitionProtocol::OntologyV2 || self.window.mode != "off" {
                return Err(ConfigError::Invalid);
            }
            graph.validate_shape(self.provider_timeout_seconds)?;
        }
        if let Some(source) = &self.entity_source {
            if source.graphs.is_empty()
                || source.identifying_predicates.is_empty()
                || source.graphs.len() > 32
                || source.classes.len() > 128
                || source.identifying_predicates.len() > 32
            {
                return Err(ConfigError::Invalid);
            }
            for iri in source
                .graphs
                .iter()
                .chain(&source.classes)
                .chain(&source.identifying_predicates)
            {
                invalid(Iri::new(iri))?;
            }
        } else if !self.approved_entity_iris.is_empty() {
            return Err(ConfigError::Invalid);
        }
        if let Some(manifest) = &self.ontology_briefing {
            manifest.validate().map_err(|_| ConfigError::Invalid)?;
        }
        if self.approved_entity_iris.len() > 4096 {
            return Err(ConfigError::Invalid);
        }
        for iri in &self.approved_entity_iris {
            invalid(Iri::new(iri))?;
        }
        invalid(PrincipalId::new(&self.principal))?;
        invalid(Iri::new(&self.action))?;
        invalid(ContentHash::parse(&self.ontology_catalog_root))?;
        if self.pi_command.as_os_str().is_empty()
            || self.pi_bundle.as_os_str().is_empty()
            || self
                .pi_session_log_dir
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            || self
                .ontology_ledger_path
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::UnsafePath);
        }
        for (name, converter) in &self.converters {
            if name.is_empty()
                || converter.version.is_empty()
                || converter.normalization.is_empty()
                || converter.arguments.len() > 64
            {
                return Err(ConfigError::Invalid);
            }
            invalid(ContentHash::parse(&converter.executable_hash))?;
        }
        for (name, adapter) in &self.url_adapters {
            if name.is_empty()
                || adapter.max_bytes == 0
                || adapter.max_bytes > self.max_source_bytes
                || !adapter.base_url.starts_with("https://")
            {
                return Err(ConfigError::Invalid);
            }
        }
        Ok(())
    }

    fn resolve_and_validate(&mut self, base: &Path) -> Result<()> {
        self.validate_shape()?;
        self.pi_command = resolve_config_path(base, &self.pi_command)?;
        self.pi_bundle = resolve_config_path(base, &self.pi_bundle)?;
        if let Some(path) = &mut self.pi_session_log_dir {
            *path = resolve_config_path(base, path)?;
        }
        if let Some(path) = &mut self.ontology_ledger_path {
            *path = resolve_config_path(base, path)?;
        }
        for root in &mut self.allowed_local_roots {
            *root = resolve_config_path(base, root)?;
        }
        self.allowed_local_roots.sort();
        self.allowed_local_roots.dedup();
        for converter in self.converters.values_mut() {
            converter.command = resolve_config_path(base, &converter.command)?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct InstanceConfig {
    pub schema: String,
    #[serde(default)]
    pub role: InstanceRole,
    #[serde(default)]
    pub authority: Option<AuthorityConfig>,
    #[serde(default)]
    pub semantic: Option<AuthorityConfig>,
    #[serde(default)]
    pub control: Option<AuthorityConfig>,
    pub projection: PathBuf,
    pub credential_file: PathBuf,
    pub source_root: PathBuf,
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    #[serde(default)]
    pub default_config: Option<ArtifactReference>,
    #[serde(default)]
    pub limits: ServiceLimits,
    #[serde(default)]
    pub broker: Option<BrokerConfig>,
    #[serde(default)]
    pub acquisition: Option<AcquisitionConfig>,
    #[serde(default)]
    pub chat: Option<ChatConfig>,
}
pub struct ProjectionBinding {
    pub path: PathBuf,
    pub backend: BackendId,
    pub authority: AuthorityId,
    pub graph: GraphId,
}
impl InstanceConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = BoundedFileRead::new(FILE_CAP, false)?.read(path)?;
        Self::parse(invalid(std::str::from_utf8(&bytes))?, path)
    }
    pub fn parse(text: &str, config_path: &Path) -> Result<Self> {
        if text.len() > FILE_CAP {
            return Err(ConfigError::Limit);
        }
        let base = absolute(config_path)?
            .parent()
            .ok_or(ConfigError::UnsafePath)?
            .to_owned();
        let mut c: Self = invalid(toml::from_str(text))?;
        let lifetime_cap = match c.schema.as_str() {
            "ctxql-instance/v1"
                if c.broker.is_none()
                    && c.acquisition.is_none()
                    && c.chat.is_none()
                    && c.authority.is_some()
                    && c.semantic.is_none()
                    && c.control.is_none() =>
            {
                300
            }
            "ctxql-instance/v2"
                if c.acquisition.is_none()
                    && c.chat.is_none()
                    && c.authority.is_some()
                    && c.semantic.is_none()
                    && c.control.is_none() =>
            {
                86_400
            }
            "ctxql-instance/v3"
                if c.acquisition.is_none()
                    && c.authority.is_none()
                    && c.semantic.is_some()
                    && c.control.is_some() =>
            {
                86_400
            }
            "ctxql-instance/v4"
                if c.authority.is_none()
                    && c.semantic.is_some()
                    && c.control.is_some()
                    && c.acquisition.is_some() =>
            {
                86_400
            }
            _ => return Err(ConfigError::Invalid),
        };
        if !c.bind.ip().is_loopback() {
            return Err(ConfigError::Invalid);
        }
        for authority in [
            c.authority.as_ref(),
            c.semantic.as_ref(),
            c.control.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_authority(authority)?;
        }
        c.limits.validate_with_lifetime_cap(lifetime_cap)?;
        for p in [
            &mut c.projection,
            &mut c.credential_file,
            &mut c.source_root,
        ] {
            if p.as_os_str().is_empty() {
                return Err(ConfigError::UnsafePath);
            }
            *p = absolute(&base.join(&*p))?;
        }
        for authority in [
            c.authority.as_mut(),
            c.semantic.as_mut(),
            c.control.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            if authority.path.as_os_str().is_empty() {
                return Err(ConfigError::UnsafePath);
            }
            authority.path = absolute(&base.join(&authority.path))?;
        }
        if let Some(acquisition) = &mut c.acquisition {
            acquisition.resolve_and_validate(&base)?;
        }
        if let Some(chat) = &mut c.chat {
            chat.resolve_and_validate(&base, c.limits.deadline_seconds, c.limits.max_work)?;
        }
        c.validate_role_separation()?;
        if let Some(broker) = &mut c.broker {
            broker.resolve_paths(&base)?;
            broker.validate_shape().map_err(|e| match e {
                StartupError::Config(e) => e,
                StartupError::Limit(_) => ConfigError::Limit,
                StartupError::UnsupportedControl(_) => ConfigError::Unsupported,
                StartupError::Invalid(_) | StartupError::Broker(_) => ConfigError::Invalid,
            })?;
        }
        c.authority_options()?;
        if let Some(r) = &c.default_config {
            r.artifact_ref()?;
        }
        c.validate_graph_workspace_binding()?;
        Ok(c)
    }
    /// Recheck public settings at the actual service boundary, including values
    /// constructed or modified by a trusted library embedder after parsing.
    pub fn validate_runtime(&self) -> Result<()> {
        let cap = match self.schema.as_str() {
            "ctxql-instance/v1"
                if self.broker.is_none()
                    && self.acquisition.is_none()
                    && self.chat.is_none()
                    && self.authority.is_some()
                    && self.semantic.is_none()
                    && self.control.is_none() =>
            {
                300
            }
            "ctxql-instance/v2"
                if self.acquisition.is_none()
                    && self.chat.is_none()
                    && self.authority.is_some()
                    && self.semantic.is_none()
                    && self.control.is_none() =>
            {
                86_400
            }
            "ctxql-instance/v3"
                if self.acquisition.is_none()
                    && self.authority.is_none()
                    && self.semantic.is_some()
                    && self.control.is_some() =>
            {
                86_400
            }
            "ctxql-instance/v4"
                if self.authority.is_none()
                    && self.semantic.is_some()
                    && self.control.is_some()
                    && self.acquisition.is_some() =>
            {
                86_400
            }
            _ => return Err(ConfigError::Invalid),
        };
        self.limits.validate_with_lifetime_cap(cap)?;
        if !self.bind.ip().is_loopback() {
            return Err(ConfigError::Invalid);
        }
        for authority in [
            self.authority.as_ref(),
            self.semantic.as_ref(),
            self.control.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_authority(authority)?;
        }
        self.validate_role_separation()?;
        if let Some(acquisition) = &self.acquisition {
            acquisition.validate_shape()?;
            if [
                Some(&acquisition.pi_command),
                Some(&acquisition.pi_bundle),
                acquisition.pi_session_log_dir.as_ref(),
                acquisition.ontology_ledger_path.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|path| !path.is_absolute())
                || acquisition
                    .allowed_local_roots
                    .iter()
                    .any(|path| !path.is_absolute())
                || acquisition
                    .converters
                    .values()
                    .any(|converter| !converter.command.is_absolute())
            {
                return Err(ConfigError::UnsafePath);
            }
        }
        if let Some(chat) = &self.chat {
            chat.validate_shape(self.limits.deadline_seconds, self.limits.max_work)?;
            if !chat.pi_command.is_absolute()
                || !chat.pi_bundle.is_absolute()
                || chat
                    .pi_session_log_dir
                    .as_ref()
                    .is_some_and(|path| !path.is_absolute())
                || chat
                    .ontology
                    .as_ref()
                    .is_some_and(|ontology| !ontology.bootstrap_path.is_absolute())
            {
                return Err(ConfigError::UnsafePath);
            }
        }
        if let Some(broker) = &self.broker {
            broker.validate_shape().map_err(|_| ConfigError::Invalid)?;
        }
        if let Some(reference) = &self.default_config {
            reference.artifact_ref()?;
        }
        self.validate_graph_workspace_binding()?;
        self.authority_options()?;
        Ok(())
    }
    fn validate_graph_workspace_binding(&self) -> Result<()> {
        let Some(graph) = self
            .acquisition
            .as_ref()
            .and_then(|acquisition| acquisition.graph_workspace.as_ref())
        else {
            return Ok(());
        };
        if graph.query_timeout_seconds > self.limits.deadline_seconds {
            return Err(ConfigError::Invalid);
        }
        match &graph.query_config {
            Some(reference) => {
                reference.artifact_ref()?;
            }
            None => {
                self.required_default_config()?;
            }
        }
        if let Some(reference) = &graph.profile {
            reference.artifact_ref()?;
        }
        Ok(())
    }
    /// Construction hook for the parent-owned Service composition. This loads the
    /// credential table and exact manifest bytes and creates all broker gates/adapters.
    pub fn startup_bundle(
        &self,
        adapters: &AdapterCatalog,
    ) -> std::result::Result<StartupBundle, StartupError> {
        startup::build(self, adapters)
    }
    pub fn required_default_config(&self) -> Result<ArtifactRef> {
        self.default_config
            .as_ref()
            .ok_or(ConfigError::Invalid)?
            .artifact_ref()
    }
    pub fn authority_options(&self) -> Result<AuthorityOptions> {
        let authority = if matches!(
            self.schema.as_str(),
            "ctxql-instance/v3" | "ctxql-instance/v4"
        ) {
            self.control.as_ref()
        } else {
            self.authority.as_ref()
        }
        .ok_or(ConfigError::Invalid)?;
        authority_options(authority)
    }
    pub fn semantic_binding(&self) -> Result<(&Path, SemanticLedgerOptions)> {
        let semantic = self.semantic.as_ref().ok_or(ConfigError::Invalid)?;
        Ok((
            &semantic.path,
            SemanticLedgerOptions {
                backend: invalid(BackendId::new(&semantic.backend))?,
                authority: invalid(AuthorityId::new(&semantic.authority))?,
                ledger: invalid(GraphId::new(&semantic.ledger))?,
            },
        ))
    }
    fn validate_role_separation(&self) -> Result<()> {
        let (Some(semantic), Some(control)) = (&self.semantic, &self.control) else {
            return Ok(());
        };
        if semantic.path == control.path
            || semantic.backend == control.backend
            || semantic.authority == control.authority
            || semantic.ledger == control.ledger
            || semantic.graph == control.graph
        {
            return Err(ConfigError::Invalid);
        }
        if self.source_root == self.projection
            || self.source_root == semantic.path
            || self.source_root == control.path
            || self.projection == semantic.path
            || self.projection == control.path
        {
            return Err(ConfigError::Invalid);
        }
        if let Some(acquisition) = &self.acquisition {
            if acquisition.pi_bundle == self.source_root
                || acquisition.pi_bundle == self.projection
                || acquisition.allowed_local_roots.iter().any(|root| {
                    root == &self.source_root
                        || root == &self.projection
                        || root == &semantic.path
                        || root == &control.path
                })
            {
                return Err(ConfigError::Invalid);
            }
        }
        if let Some(chat) = &self.chat {
            let protected = [
                &self.source_root,
                &self.projection,
                &semantic.path,
                &control.path,
            ]
            .into_iter()
            .map(|path| separation_path(path))
            .collect::<Result<Vec<_>>>()?;
            let overlaps = |a: &Path, b: &Path| a.starts_with(b) || b.starts_with(a);
            for (index, path) in protected.iter().enumerate() {
                if protected[..index].iter().any(|other| overlaps(path, other)) {
                    return Err(ConfigError::Invalid);
                }
            }
            // Compare canonical existing prefixes, including runtime-constructed
            // configs. Reject symlink aliases before opening any native stores.
            let bundle = separation_path(&chat.pi_bundle)?;
            let ontology = chat
                .ontology
                .as_ref()
                .map(|ontology| separation_path(&ontology.bootstrap_path))
                .transpose()?;
            if protected.iter().any(|path| {
                overlaps(path, &bundle)
                    || ontology
                        .as_ref()
                        .is_some_and(|ontology| overlaps(path, ontology))
            }) {
                return Err(ConfigError::Invalid);
            }
        }
        // Either producer can log sensitive content from the whole instance.
        // Check both destinations against all configured resources, not only
        // the resources belonging to that producer. Keep logging-off unchanged.
        for log_dir in [
            self.chat
                .as_ref()
                .and_then(|chat| chat.pi_session_log_dir.as_ref()),
            self.acquisition
                .as_ref()
                .and_then(|acquisition| acquisition.pi_session_log_dir.as_ref()),
        ]
        .into_iter()
        .flatten()
        {
            let log_dir = separation_path(log_dir)?;
            let mut protected = vec![
                &self.source_root,
                &self.projection,
                &semantic.path,
                &control.path,
            ];
            if let Some(acquisition) = &self.acquisition {
                protected.push(&acquisition.pi_bundle);
                protected.extend(acquisition.ontology_ledger_path.iter());
                protected.extend(acquisition.allowed_local_roots.iter());
            }
            if let Some(chat) = &self.chat {
                protected.push(&chat.pi_bundle);
                if let Some(ontology) = &chat.ontology {
                    protected.push(&ontology.bootstrap_path);
                }
            }
            for path in protected {
                let path = separation_path(path)?;
                if log_dir.starts_with(&path) || path.starts_with(&log_dir) {
                    return Err(ConfigError::Invalid);
                }
            }
        }
        Ok(())
    }
    pub fn projection_binding(&self) -> Result<ProjectionBinding> {
        if matches!(
            self.schema.as_str(),
            "ctxql-instance/v3" | "ctxql-instance/v4"
        ) {
            let (_, semantic) = self.semantic_binding()?;
            return Ok(ProjectionBinding {
                path: self.projection.clone(),
                backend: semantic.backend,
                authority: semantic.authority,
                graph: semantic.ledger,
            });
        }
        let a = self.authority_options()?;
        Ok(ProjectionBinding {
            path: self.projection.clone(),
            backend: a.backend,
            authority: a.authority,
            graph: a.graph,
        })
    }
}

fn validate_authority(authority: &AuthorityConfig) -> Result<()> {
    if authority.ledger.is_empty() || authority.ledger.len() > 256 {
        return Err(ConfigError::Invalid);
    }
    authority_options(authority).map(drop)
}

fn authority_options(authority: &AuthorityConfig) -> Result<AuthorityOptions> {
    Ok(AuthorityOptions::new(
        authority.path.clone(),
        authority.ledger.clone(),
        invalid(BackendId::new(&authority.backend))?,
        invalid(AuthorityId::new(&authority.authority))?,
        invalid(GraphId::new(&authority.graph))?,
    ))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialEntry {
    pub digest: String,
    pub principal: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub capabilities: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialTable {
    pub schema: String,
    pub entries: Vec<CredentialEntry>,
}
impl CredentialTable {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > FILE_CAP {
            return Err(ConfigError::Limit);
        }
        let t: Self = invalid(serde_json::from_slice(bytes))?;
        t.auth_store(Duration::from_secs(300))?;
        Ok(t)
    }
    pub fn load(path: &Path) -> Result<Self> {
        Self::parse(&BoundedFileRead::new(FILE_CAP, true)?.read(path)?)
    }
    pub fn auth_store(&self, ttl: Duration) -> Result<AuthStore> {
        if self.schema != "ctxql-credentials/v1"
            || self.entries.len() > crate::auth::MAX_CREDENTIALS
        {
            return Err(ConfigError::Invalid);
        }
        let records = self
            .entries
            .iter()
            .map(|e| {
                let mut ops = Vec::new();
                for s in &e.capabilities {
                    let op = match s.as_str() {
                        "query" => Operation::Query,
                        "read" => Operation::Read,
                        "replay" => Operation::Replay,
                        "publish" => Operation::Publish,
                        "admin" => Operation::Admin,
                        _ => return Err(ConfigError::Invalid),
                    };
                    if ops.contains(&op) {
                        return Err(ConfigError::Invalid);
                    }
                    ops.push(op);
                }
                let expires = e
                    .expires_at
                    .as_ref()
                    .map(|s| {
                        if !s.ends_with('Z') {
                            return Err(ConfigError::Invalid);
                        }
                        let ms = invalid(Timestamp::parse(s))?.millis();
                        if ms >= 0 {
                            UNIX_EPOCH.checked_add(Duration::from_millis(ms as u64))
                        } else {
                            UNIX_EPOCH.checked_sub(Duration::from_millis(ms.unsigned_abs()))
                        }
                        .ok_or(ConfigError::Invalid)
                    })
                    .transpose()?;
                invalid(CredentialRecord::new(
                    &e.digest,
                    invalid(PrincipalId::new(&e.principal))?,
                    e.enabled,
                    expires,
                    Capabilities::only(&ops),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        invalid(AuthStore::new(records, ttl))
    }
    pub fn write_new(&self, path: &Path) -> Result<()> {
        self.auth_store(Duration::from_secs(300))?;
        let bytes = invalid(serde_json::to_vec(self))?;
        if bytes.len() > FILE_CAP {
            return Err(ConfigError::Limit);
        }
        create_secret_file(path, &bytes)
    }
}
pub(crate) fn resolve_config_path(base: &Path, path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::UnsafePath);
    }
    absolute(&base.join(path))
}
/// Resolve the existing prefix without allowing symlinks, preserving absent
/// suffixes for configurations whose disposable stores have not been created.
fn separation_path(path: &Path) -> Result<PathBuf> {
    let normalized = absolute(path)?;
    let mut existing = normalized.as_path();
    let mut suffix = Vec::new();
    loop {
        match fs::symlink_metadata(existing) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(ConfigError::UnsafePath);
                }
                if existing.parent().is_some() {
                    ancestors(existing)?;
                }
                let mut resolved = fs::canonicalize(existing).map_err(|_| ConfigError::Io)?;
                for component in suffix.into_iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                suffix.push(
                    existing
                        .file_name()
                        .ok_or(ConfigError::UnsafePath)?
                        .to_owned(),
                );
                existing = existing.parent().ok_or(ConfigError::UnsafePath)?;
            }
            Err(_) => return Err(ConfigError::UnsafePath),
        }
    }
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(ConfigError::UnsafePath);
    }
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                if !out.pop() {
                    return Err(ConfigError::UnsafePath);
                }
            }
            Component::CurDir => {}
            _ => out.push(c.as_os_str()),
        }
    }
    Ok(out)
}
#[cfg(unix)]
fn identity(a: &Metadata, b: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
#[cfg(not(unix))]
fn identity(_: &Metadata, _: &Metadata) -> bool {
    false
}
fn ancestors(path: &Path) -> Result<Vec<(PathBuf, Metadata)>> {
    let mut chain = Vec::new();
    for p in path.parent().ok_or(ConfigError::UnsafePath)?.ancestors() {
        let m = fs::symlink_metadata(p).map_err(|_| ConfigError::Io)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(ConfigError::UnsafePath);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0 {
                return Err(ConfigError::UnsafePath);
            }
        }
        chain.push((p.to_owned(), m));
    }
    Ok(chain)
}
fn check_ancestors(chain: &[(PathBuf, Metadata)]) -> Result<()> {
    // Directory size/times legitimately change when creating the destination.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for (p, m) in chain {
            let n = fs::symlink_metadata(p).map_err(|_| ConfigError::Io)?;
            if !n.is_dir()
                || n.file_type().is_symlink()
                || n.dev() != m.dev()
                || n.ino() != m.ino()
                || n.mode() != m.mode()
                || n.uid() != m.uid()
            {
                return Err(ConfigError::UnsafePath);
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = chain;
        Err(ConfigError::Unsupported)
    }
}
fn check_file(m: &Metadata, private: bool) -> Result<()> {
    if !m.is_file() || m.file_type().is_symlink() {
        return Err(ConfigError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if private && (m.mode() & 0o777 != 0o600 || m.nlink() != 1) {
            return Err(ConfigError::UnsafePath);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = private;
        Err(ConfigError::Unsupported)
    }
}
pub struct BoundedFileRead {
    max_bytes: usize,
    private: bool,
}
impl BoundedFileRead {
    pub fn new(max_bytes: usize, private: bool) -> Result<Self> {
        if max_bytes == 0 || max_bytes > 16 * FILE_CAP {
            return Err(ConfigError::Limit);
        }
        Ok(Self { max_bytes, private })
    }
    pub fn read(&self, path: &Path) -> Result<Vec<u8>> {
        if !cfg!(unix) {
            return Err(ConfigError::Unsupported);
        }
        let path = absolute(path)?;
        let chain = ancestors(&path)?;
        let before = fs::symlink_metadata(&path).map_err(|_| ConfigError::Io)?;
        check_file(&before, self.private)?;
        if before.len() > self.max_bytes as u64 {
            return Err(ConfigError::Limit);
        }
        let mut f = File::open(&path).map_err(|_| ConfigError::Io)?;
        let opened = f.metadata().map_err(|_| ConfigError::Io)?;
        check_file(&opened, self.private)?;
        if !identity(&before, &opened) {
            return Err(ConfigError::UnsafePath);
        }
        check_ancestors(&chain)?;
        let mut bytes = Vec::new();
        (&mut f)
            .take(self.max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ConfigError::Io)?;
        if bytes.len() > self.max_bytes {
            return Err(ConfigError::Limit);
        }
        let after = f.metadata().map_err(|_| ConfigError::Io)?;
        let named = fs::symlink_metadata(&path).map_err(|_| ConfigError::Io)?;
        if !identity(&opened, &after)
            || !identity(&after, &named)
            || bytes.len() as u64 != after.len()
        {
            return Err(ConfigError::UnsafePath);
        }
        check_ancestors(&chain)?;
        Ok(bytes)
    }
}
/// Trusted provisioning only. No overwrite, including dangling symlinks.
pub fn create_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if !cfg!(unix) {
        return Err(ConfigError::Unsupported);
    }
    if bytes.len() > FILE_CAP {
        return Err(ConfigError::Limit);
    }
    let path = absolute(path)?;
    let chain = ancestors(&path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(&path).map_err(|_| ConfigError::Io)?;
    let opened = f.metadata().map_err(|_| ConfigError::Io)?;
    check_file(&opened, true)?;
    check_ancestors(&chain)?;
    if !identity(
        &opened,
        &fs::symlink_metadata(&path).map_err(|_| ConfigError::Io)?,
    ) {
        return Err(ConfigError::UnsafePath);
    }
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| ConfigError::Io)?;
    let after = f.metadata().map_err(|_| ConfigError::Io)?;
    check_file(&after, true)?;
    if !identity(
        &after,
        &fs::symlink_metadata(&path).map_err(|_| ConfigError::Io)?,
    ) {
        return Err(ConfigError::UnsafePath);
    }
    check_ancestors(&chain)
}
