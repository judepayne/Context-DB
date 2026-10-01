//! Strict `ctxql-instance/v2` broker configuration and startup construction.
//! Secrets are consumed into adapters and are never retained in resolved settings.
use super::{
    dispatch::{Adapter, ExecutionClass},
    http::{HttpJsonAdapter, SecretString},
    limits::{BrokerLimits, ResourceLimits},
    registry::{ProviderRegistration, Registry},
    Broker, BrokerSettings,
};
use crate::auth::AuthStore;
use crate::config::{ArtifactReference, BoundedFileRead, ConfigError, CredentialTable};
use cdb_core::{
    artifact::PublishedArtifact,
    function_manifest::ExternalFunctionManifest,
    id::{ContentHash, ResourceId},
    Error, Limits,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};

const MIB: usize = 1024 * 1024;
const MAX_WORKERS: usize = 1024;
const MAX_PENDING_BYTES: usize = 1024 * MIB;
const MAX_VALUE_BYTES: usize = 16 * MIB;
const MAX_CALLS: u64 = 100_000_000;
const MAX_SCRIPT_OPERATIONS: u64 = 1_000_000_000;

#[derive(Debug)]
pub enum StartupError {
    Config(ConfigError),
    Invalid(&'static str),
    Limit(&'static str),
    UnsupportedControl(&'static str),
    Broker(Error),
}
impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(e) => e.fmt(f),
            Self::Invalid(s) => write!(f, "invalid startup configuration: {s}"),
            Self::Limit(s) => write!(f, "startup configuration limit: {s}"),
            Self::UnsupportedControl(s) => write!(f, "unsupported startup control: {s}"),
            Self::Broker(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for StartupError {}
impl From<StartupError> for Error {
    fn from(value: StartupError) -> Self {
        use cdb_core::ErrorKind;
        let kind = match &value {
            StartupError::Config(ConfigError::Limit) | StartupError::Limit(_) => ErrorKind::Limit,
            StartupError::Config(ConfigError::UnsafePath) => ErrorKind::Denied,
            StartupError::Config(ConfigError::Io) => ErrorKind::Backend,
            StartupError::Config(ConfigError::Unsupported)
            | StartupError::UnsupportedControl(_) => ErrorKind::Unsupported,
            StartupError::Config(ConfigError::Invalid) | StartupError::Invalid(_) => {
                ErrorKind::Invalid
            }
            StartupError::Broker(error) => return error.clone(),
        };
        Error::new(kind, value.to_string())
    }
}
impl From<ConfigError> for StartupError {
    fn from(v: ConfigError) -> Self {
        Self::Config(v)
    }
}
impl From<Error> for StartupError {
    fn from(v: Error) -> Self {
        Self::Broker(v)
    }
}
type Result<T> = std::result::Result<T, StartupError>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderClass {
    HttpService,
    CpuBlocking,
    Accelerator,
}
impl ProviderClass {
    fn execution(self) -> ExecutionClass {
        match self {
            Self::HttpService => ExecutionClass::HttpService,
            Self::CpuBlocking => ExecutionClass::CpuBlocking,
            Self::Accelerator => ExecutionClass::Accelerator,
        }
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceConfig {
    pub max_in_flight: Option<usize>,
    pub max_queued_bytes: Option<usize>,
    pub requests_per_second: Option<u32>,
    pub burst_requests: Option<u32>,
    /// Reserved schema surface. Current dispatch has no trustworthy token quantity.
    pub tokens_per_second: Option<u64>,
    pub burst_tokens: Option<u64>,
    pub token_accounting: Option<String>,
}
impl ResourceConfig {
    fn resolve(&self, parent: ResourceLimits) -> Result<ResourceLimits> {
        if self.tokens_per_second.is_some()
            || self.burst_tokens.is_some()
            || self.token_accounting.is_some()
        {
            return Err(StartupError::UnsupportedControl(
                "token rates require dispatch token accounting capability",
            ));
        }
        let v = ResourceLimits {
            max_in_flight: self.max_in_flight.unwrap_or(parent.max_in_flight),
            max_queued_bytes: self.max_queued_bytes.unwrap_or(parent.max_queued_bytes),
            requests_per_second: self
                .requests_per_second
                .unwrap_or(parent.requests_per_second),
            burst_requests: self.burst_requests.unwrap_or(parent.burst_requests),
        };
        if v.max_in_flight > MAX_WORKERS || v.max_queued_bytes > MAX_PENDING_BYTES {
            return Err(StartupError::Limit("resource permits or queued bytes"));
        }
        v.validate().map_err(StartupError::Broker)
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestConfig {
    #[serde(flatten)]
    pub artifact: ArtifactReference,
    pub file: PathBuf,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub class: ProviderClass,
    pub adapter: String,
    pub destination: String,
    pub group: String,
    pub allowed_manifests: Vec<String>,
    #[serde(default)]
    pub resources: ResourceConfig,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub allow_loopback_plaintext: bool,
    #[serde(default)]
    pub credential_file: Option<PathBuf>,
    pub implementation: String,
    pub implementation_version: String,
    pub implementation_build: String,
    #[serde(default)]
    pub workers: Option<usize>,
    #[serde(default)]
    pub internal_threads: Option<usize>,
    #[serde(default)]
    pub device_memory_bytes: Option<usize>,
    #[serde(default)]
    pub max_batch: Option<usize>,
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScriptLimits {
    pub max_operations: u64,
    pub max_recursion: usize,
    pub max_ast_bytes: usize,
    pub max_container_items: usize,
}
impl Default for ScriptLimits {
    fn default() -> Self {
        Self {
            max_operations: 10_000_000,
            max_recursion: 64,
            max_ast_bytes: MIB,
            max_container_items: 100_000,
        }
    }
}
impl ScriptLimits {
    fn validate(&self) -> Result<()> {
        if self.max_operations == 0
            || self.max_operations > MAX_SCRIPT_OPERATIONS
            || self.max_recursion == 0
            || self.max_recursion > 1024
            || self.max_ast_bytes == 0
            || self.max_ast_bytes > 16 * MIB
            || self.max_container_items == 0
            || self.max_container_items > 10_000_000
        {
            return Err(StartupError::Limit(
                "script operations/recursion/AST/container",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrokerConfig {
    pub enabled: bool,
    pub rhai_workers: usize,
    pub local_workers: usize,
    pub per_request_pending: usize,
    pub global_pending_bytes: usize,
    pub per_request_pending_bytes: usize,
    pub max_logical_calls: u64,
    pub max_argument_bytes: usize,
    pub max_result_bytes: usize,
    pub max_state_bytes: usize,
    pub call_timeout_ms: u64,
    pub max_attempts: u8,
    pub global: ResourceConfig,
    pub script: ScriptLimits,
    pub groups: BTreeMap<String, ResourceConfig>,
    pub manifests: BTreeMap<String, ManifestConfig>,
    pub providers: BTreeMap<String, ProviderConfig>,
}
impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rhai_workers: 32,
            local_workers: 2,
            per_request_pending: 64,
            global_pending_bytes: 64 * MIB,
            per_request_pending_bytes: 64 * MIB,
            max_logical_calls: 250_000,
            max_argument_bytes: 256 * 1024,
            max_result_bytes: MIB,
            max_state_bytes: 64 * 1024,
            call_timeout_ms: 30_000,
            max_attempts: 2,
            global: ResourceConfig::default(),
            script: ScriptLimits::default(),
            groups: BTreeMap::new(),
            manifests: BTreeMap::new(),
            providers: BTreeMap::new(),
        }
    }
}
impl BrokerConfig {
    pub(crate) fn resolve_paths(
        &mut self,
        base: &std::path::Path,
    ) -> std::result::Result<(), ConfigError> {
        for manifest in self.manifests.values_mut() {
            manifest.file = crate::config::resolve_config_path(base, &manifest.file)?;
        }
        for provider in self.providers.values_mut() {
            if let Some(path) = &mut provider.credential_file {
                *path = crate::config::resolve_config_path(base, path)?;
            }
        }
        Ok(())
    }
    pub fn validate_shape(&self) -> Result<()> {
        self.script.validate()?;
        if !self.enabled {
            if !self.groups.is_empty() || !self.manifests.is_empty() || !self.providers.is_empty() {
                return Err(StartupError::Invalid(
                    "disabled broker cannot declare groups, manifests, or providers",
                ));
            }
            return Ok(());
        }
        if self.rhai_workers == 0
            || self.local_workers == 0
            || self.rhai_workers > MAX_WORKERS
            || self.local_workers > MAX_WORKERS
        {
            return Err(StartupError::Limit("worker counts"));
        }
        if self.per_request_pending == 0 || self.per_request_pending > 1_000_000 {
            return Err(StartupError::Limit("per-request pending count"));
        }
        for (v, label, cap) in [
            (
                self.global_pending_bytes,
                "global pending bytes",
                MAX_PENDING_BYTES,
            ),
            (
                self.per_request_pending_bytes,
                "per-request pending bytes",
                MAX_PENDING_BYTES,
            ),
            (self.max_argument_bytes, "argument bytes", MAX_VALUE_BYTES),
            (self.max_result_bytes, "result bytes", MAX_VALUE_BYTES),
            (self.max_state_bytes, "state bytes", MAX_VALUE_BYTES),
        ] {
            if v == 0 || v > cap {
                return Err(StartupError::Limit(label));
            }
        }
        if self.per_request_pending_bytes > self.global_pending_bytes {
            return Err(StartupError::Invalid(
                "per-request pending bytes exceed global budget",
            ));
        }
        if self
            .max_argument_bytes
            .checked_add(self.max_result_bytes)
            .is_none_or(|n| n > self.per_request_pending_bytes)
        {
            return Err(StartupError::Invalid(
                "one call reservation exceeds per-request pending bytes",
            ));
        }
        if self.max_logical_calls == 0 || self.max_logical_calls > MAX_CALLS {
            return Err(StartupError::Limit("logical calls"));
        }
        if self.call_timeout_ms == 0 || self.call_timeout_ms > 86_400_000 {
            return Err(StartupError::Limit("call deadline"));
        }
        if self.max_attempts == 0 || self.max_attempts > 8 {
            return Err(StartupError::Limit("attempts"));
        }
        if self.groups.is_empty() || self.manifests.is_empty() || self.providers.is_empty() {
            return Err(StartupError::Invalid(
                "enabled broker requires groups, manifests, and providers",
            ));
        }
        Ok(())
    }
}

/// Fixed physical adapter capacity declared by the trusted host registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCapacity {
    pub workers: usize,
    pub internal_threads: usize,
    pub device_memory_bytes: Option<usize>,
    pub max_batch: Option<usize>,
    pub test_only: bool,
}
struct CatalogEntry {
    adapter: Arc<dyn Adapter>,
    capacity: NativeCapacity,
}
#[derive(Default)]
pub struct AdapterCatalog {
    entries: BTreeMap<String, CatalogEntry>,
}
impl AdapterCatalog {
    pub fn register(
        &mut self,
        id: &str,
        adapter: Arc<dyn Adapter>,
        capacity: NativeCapacity,
    ) -> Result<()> {
        if id.is_empty()
            || capacity.workers == 0
            || capacity.internal_threads == 0
            || self.entries.contains_key(id)
        {
            return Err(StartupError::Invalid(
                "invalid or duplicate native adapter registration",
            ));
        }
        self.entries
            .insert(id.into(), CatalogEntry { adapter, capacity });
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorSettings {
    pub rhai_workers: usize,
    pub local_workers: usize,
    pub global_pending_bytes: usize,
    pub per_request_pending: usize,
    pub per_request_pending_bytes: usize,
    pub max_state_bytes: usize,
    pub script_max_operations: u64,
    pub script_max_recursion: usize,
    pub script_max_ast_bytes: usize,
    pub script_max_container_items: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedProvider {
    pub id: String,
    pub class: ProviderClass,
    pub adapter: String,
    pub group: String,
    pub adapter_build: String,
    pub test_only: bool,
}
pub struct StartupBundle {
    pub auth: AuthStore,
    pub broker: Broker,
    pub executor: ExecutorSettings,
    pub providers: Vec<ResolvedProvider>,
}

pub fn build(
    config: &crate::config::InstanceConfig,
    catalog: &AdapterCatalog,
) -> Result<StartupBundle> {
    let auth =
        CredentialTable::load(&config.credential_file)?.auth_store(config.limits.session_ttl())?;
    build_with_auth(config, catalog, auth)
}

/// Embedding hook: retain the supplied issuer rather than loading a second one.
pub fn build_with_auth(
    config: &crate::config::InstanceConfig,
    catalog: &AdapterCatalog,
    auth: AuthStore,
) -> Result<StartupBundle> {
    config.validate_runtime()?;
    let broker_config = config.broker.as_ref().cloned().unwrap_or_default();
    broker_config.validate_shape()?;
    if !broker_config.enabled {
        return Ok(StartupBundle {
            auth,
            broker: Broker::new(
                Registry::new(vec![], vec![])?,
                BrokerSettings::disabled(),
                &BTreeMap::new(),
            )?,
            executor: executor(&broker_config),
            providers: vec![],
        });
    }
    let base_global = BrokerLimits::default().global;
    let mut global = broker_config.global.resolve(base_global)?;
    global.max_queued_bytes = global
        .max_queued_bytes
        .min(broker_config.global_pending_bytes);
    let mut groups = BTreeMap::new();
    for (id, value) in &broker_config.groups {
        ResourceId::new(id).map_err(StartupError::Broker)?;
        groups.insert(id.clone(), value.resolve(global)?);
    }
    let mut manifests = Vec::new();
    let mut manifest_bindings = BTreeMap::new();
    let mut manifest_implementations = BTreeMap::new();
    for (id, value) in &broker_config.manifests {
        if id.is_empty() {
            return Err(StartupError::Invalid("empty manifest alias"));
        }
        let reference = value.artifact.artifact_ref()?;
        let bytes = BoundedFileRead::new(16 * MIB, true)?.read(&value.file)?;
        let published = PublishedArtifact::new(reference, bytes, Limits::default())?;
        let manifest = ExternalFunctionManifest::from_published(&published, Limits::default())?;
        manifest_bindings.insert(
            id.clone(),
            ProviderRegistration::binding(manifest.artifact()),
        );
        manifest_implementations.insert(
            id.clone(),
            (
                manifest.implementation().implementation.as_str().to_owned(),
                manifest.implementation().version.as_str().to_owned(),
                manifest.implementation().build.clone(),
            ),
        );
        manifests.push(manifest);
    }
    let mut registrations = Vec::new();
    let mut provider_limits = BTreeMap::new();
    let mut resolved = Vec::new();
    for (id, value) in &broker_config.providers {
        let provider_id = ResourceId::new(id).map_err(StartupError::Broker)?;
        let destination = ResourceId::new(&value.destination).map_err(StartupError::Broker)?;
        let group = ResourceId::new(&value.group).map_err(StartupError::Broker)?;
        let group_limits = *groups
            .get(&value.group)
            .ok_or(StartupError::Invalid("provider references unknown group"))?;
        let limits = value.resources.resolve(group_limits)?;
        let allowed_manifests = value
            .allowed_manifests
            .iter()
            .map(|name| {
                manifest_bindings
                    .get(name)
                    .cloned()
                    .ok_or(StartupError::Invalid(
                        "provider references unknown manifest alias",
                    ))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if allowed_manifests.len() != value.allowed_manifests.len() || allowed_manifests.is_empty()
        {
            return Err(StartupError::Invalid(
                "empty or duplicate provider manifest allowlist",
            ));
        }
        let implementation_build =
            ContentHash::parse(&value.implementation_build).map_err(StartupError::Broker)?;
        for alias in &value.allowed_manifests {
            let identity = manifest_implementations
                .get(alias)
                .ok_or(StartupError::Invalid(
                    "provider references unknown manifest alias",
                ))?;
            if identity.0 != value.implementation
                || identity.1 != value.implementation_version
                || identity.2 != implementation_build
            {
                return Err(StartupError::Invalid(
                    "provider implementation identity does not match exact manifest",
                ));
            }
        }
        let (adapter, test_only) =
            match value.class {
                ProviderClass::HttpService => {
                    if value.adapter != "ctxql-http-json/v1" {
                        return Err(StartupError::UnsupportedControl("unknown HTTP adapter"));
                    }
                    if value.workers.is_some()
                        || value.internal_threads.is_some()
                        || value.device_memory_bytes.is_some()
                        || value.max_batch.is_some()
                    {
                        return Err(StartupError::Invalid(
                            "HTTP provider contains native capacity controls",
                        ));
                    }
                    let credential = value
                        .credential_file
                        .as_ref()
                        .map(|path| {
                            BoundedFileRead::new(MIB, true)?.read(path).and_then(|b| {
                                String::from_utf8(b).map_err(|_| ConfigError::Invalid)
                            })
                        })
                        .transpose()?
                        .map(SecretString::new)
                        .transpose()?;
                    let endpoint = value
                        .endpoint
                        .as_deref()
                        .ok_or(StartupError::Invalid("HTTP provider requires endpoint"))?;
                    (
                        Arc::new(HttpJsonAdapter::new(
                            endpoint,
                            value.allow_loopback_plaintext,
                            credential,
                            limits.max_in_flight,
                            value.implementation.clone(),
                            value.implementation_version.clone(),
                            implementation_build,
                        )?) as Arc<dyn Adapter>,
                        false,
                    )
                }
                class => {
                    if value.endpoint.is_some()
                        || value.credential_file.is_some()
                        || value.allow_loopback_plaintext
                    {
                        return Err(StartupError::Invalid(
                            "native provider contains HTTP controls",
                        ));
                    }
                    let entry = catalog.entries.get(&value.adapter).ok_or(
                        StartupError::UnsupportedControl(
                            "configured native adapter is not registered/available",
                        ),
                    )?;
                    if entry.adapter.class() != class.execution() {
                        return Err(StartupError::Invalid("adapter execution class mismatch"));
                    }
                    let requested = NativeCapacity {
                        workers: value
                            .workers
                            .ok_or(StartupError::Invalid("native provider requires workers"))?,
                        internal_threads: value.internal_threads.ok_or(StartupError::Invalid(
                            "native provider requires internal_threads",
                        ))?,
                        device_memory_bytes: value.device_memory_bytes,
                        max_batch: value.max_batch,
                        test_only: entry.capacity.test_only,
                    };
                    if requested.workers == 0
                        || requested.internal_threads == 0
                        || requested.workers > MAX_WORKERS
                        || requested.internal_threads > MAX_WORKERS
                    {
                        return Err(StartupError::Limit("native adapter capacity"));
                    }
                    if requested.workers != entry.capacity.workers
                        || requested.internal_threads != entry.capacity.internal_threads
                        || requested.device_memory_bytes != entry.capacity.device_memory_bytes
                        || requested.max_batch != entry.capacity.max_batch
                    {
                        return Err(StartupError::UnsupportedControl(
                        "configured native capacity does not match registered adapter capability",
                    ));
                    }
                    if class == ProviderClass::Accelerator && !entry.capacity.test_only {
                        return Err(StartupError::UnsupportedControl(
                            "real accelerator adapter is not compiled/available",
                        ));
                    }
                    (entry.adapter.clone(), entry.capacity.test_only)
                }
            };
        provider_limits.insert(id.clone(), limits);
        resolved.push(ResolvedProvider {
            id: id.clone(),
            class: value.class,
            adapter: value.adapter.clone(),
            group: value.group.clone(),
            adapter_build: adapter.build_identity().into(),
            test_only,
        });
        registrations.push(ProviderRegistration {
            id: provider_id,
            destination,
            group,
            limits,
            allowed_manifests,
            adapter,
        });
    }
    let limits = BrokerLimits {
        global,
        per_request_pending: broker_config.per_request_pending,
        per_request_bytes: broker_config
            .per_request_pending_bytes
            .min(global.max_queued_bytes),
        max_logical_calls: broker_config.max_logical_calls,
        max_argument_bytes: broker_config.max_argument_bytes,
        max_result_bytes: broker_config.max_result_bytes,
        call_timeout_ms: broker_config.call_timeout_ms,
        max_attempts: broker_config.max_attempts,
    };
    let settings = BrokerSettings {
        enabled: true,
        limits,
        groups,
    };
    let broker = Broker::new(
        Registry::new(manifests, registrations)?,
        settings,
        &provider_limits,
    )?;
    let mut executor = executor(&broker_config);
    executor.global_pending_bytes = executor.global_pending_bytes.min(global.max_queued_bytes);
    executor.per_request_pending_bytes = executor
        .per_request_pending_bytes
        .min(executor.global_pending_bytes);
    Ok(StartupBundle {
        auth,
        broker,
        executor,
        providers: resolved,
    })
}
fn executor(c: &BrokerConfig) -> ExecutorSettings {
    ExecutorSettings {
        rhai_workers: c.rhai_workers,
        local_workers: c.local_workers,
        global_pending_bytes: c.global_pending_bytes,
        per_request_pending: c.per_request_pending,
        per_request_pending_bytes: c.per_request_pending_bytes,
        max_state_bytes: c.max_state_bytes,
        script_max_operations: c.script.max_operations,
        script_max_recursion: c.script.max_recursion,
        script_max_ast_bytes: c.script.max_ast_bytes,
        script_max_container_items: c.script.max_container_items,
    }
}
