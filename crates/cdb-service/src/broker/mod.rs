//! Bounded external-function broker. Startup registration fixes all semantic and
//! operational destinations; request data cannot select URLs, models, or adapters.
pub mod accelerator;
pub mod authorization_log;
pub mod cpu;
pub mod dispatch;
pub mod http;
pub mod limits;
pub mod native_authorization;
pub mod permissions;
pub mod registry;
pub mod startup;

#[cfg(test)]
mod lifetime_tests;

use cdb_core::{
    id::{Iri, ResourceId},
    CanonicalValue, Error, ErrorKind, Limits, Result,
};
use dispatch::{AttemptFailure, Cancellation, FailureClass, PhysicalRequest};
use limits::{
    BrokerLimits, FairGate, GatePermit, LogicalAdmission, LogicalLimiter, ResourceLimits,
};
use permissions::{AuthorizationAction, TrustedAuthorizer};
use registry::Registry;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    sync::oneshot,
    time::{timeout_at, Instant},
};

#[derive(Clone, Debug)]
pub struct BrokerSettings {
    pub enabled: bool,
    pub limits: BrokerLimits,
    pub groups: BTreeMap<String, ResourceLimits>,
}
impl BrokerSettings {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            limits: BrokerLimits::default(),
            groups: BTreeMap::new(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        for v in self.groups.values() {
            v.validate()?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct Invocation {
    pub session_id: String,
    pub request_id: String,
    pub logical_id: String,
    pub lane: u64,
    pub function_name: String,
    pub function_version: String,
    pub provider: String,
    /// Cumulative graph dependencies that influenced the argument.
    pub argument_dependencies: Vec<ResourceId>,
    /// Cumulative dependencies carried through predicate state from earlier work.
    pub state_dependencies: Vec<ResourceId>,
    pub fact_dependencies: Vec<(ResourceId, Iri)>,
    pub scope_dependencies: Vec<ResourceId>,
    pub input: CanonicalValue,
}

pub struct BrokerResult {
    value: CanonicalValue,
    manifest: Arc<cdb_core::function_manifest::ExternalFunctionManifest>,
    provider: Arc<registry::ProviderRegistration>,
    invocation: Invocation,
    attempt: u8,
    _reservation: LogicalAdmission,
}
pub(crate) struct ConsumedBrokerResult {
    pub value: CanonicalValue,
    pub owner: LogicalAdmission,
}
impl BrokerResult {
    /// A callback/controller must consume through this fresh authorization boundary.
    pub async fn consume(self, authorizer: &dyn TrustedAuthorizer) -> Result<CanonicalValue> {
        Ok(self.consume_retained(authorizer).await?.value)
    }
    /// Ordered function recording retains the same admission after consumption.
    pub(crate) async fn consume_retained(
        self,
        authorizer: &dyn TrustedAuthorizer,
    ) -> Result<ConsumedBrokerResult> {
        let action = AuthorizationAction {
            session_id: &self.invocation.session_id,
            request_id: &self.invocation.request_id,
            logical_id: &self.invocation.logical_id,
            attempt: self.attempt,
            manifest: &self.manifest,
            provider: &self.provider.destination,
            argument_dependencies: &self.invocation.argument_dependencies,
            state_dependencies: &self.invocation.state_dependencies,
            fact_dependencies: &self.invocation.fact_dependencies,
            scope_dependencies: &self.invocation.scope_dependencies,
        };
        authorizer.authorize_result(action, &self.value).await?;
        Ok(ConsumedBrokerResult {
            value: self.value,
            owner: self._reservation,
        })
    }
}

pub struct Broker {
    registry: Arc<Registry>,
    settings: BrokerSettings,
    logical: LogicalLimiter,
    global: Arc<FairGate>,
    groups: BTreeMap<String, Arc<FairGate>>,
    providers: BTreeMap<String, Arc<FairGate>>,
    stopping: AtomicBool,
}
impl Broker {
    pub(crate) fn reserve_evaluation(
        &self,
        request: &str,
        bytes: usize,
    ) -> Result<LogicalAdmission> {
        self.logical.reserve_evaluation(request, bytes)
    }
    pub fn new(
        registry: Registry,
        settings: BrokerSettings,
        provider_limits: &BTreeMap<String, ResourceLimits>,
    ) -> Result<Self> {
        settings.validate()?;
        let mut groups = BTreeMap::new();
        for (k, v) in &settings.groups {
            groups.insert(k.clone(), FairGate::new(v.validate()?));
        }
        let mut providers = BTreeMap::new();
        for (k, v) in provider_limits {
            providers.insert(k.clone(), FairGate::new(v.validate()?));
        }
        let limits = settings.limits;
        Ok(Self {
            registry: Arc::new(registry),
            settings,
            logical: LogicalLimiter::new(limits),
            global: FairGate::new(limits.global),
            groups,
            providers,
            stopping: AtomicBool::new(false),
        })
    }
    pub async fn invoke(
        &self,
        invocation: Invocation,
        authorizer: Arc<dyn TrustedAuthorizer>,
    ) -> Result<BrokerResult> {
        self.invoke_with_controls(invocation, authorizer, None, Cancellation::new())
            .await
    }

    /// Operational deadline/cancellation do not participate in function identity.
    pub async fn invoke_with_controls(
        &self,
        invocation: Invocation,
        authorizer: Arc<dyn TrustedAuthorizer>,
        caller_deadline: Option<Instant>,
        cancellation: Cancellation,
    ) -> Result<BrokerResult> {
        if !self.settings.enabled {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "function broker disabled",
            ));
        }
        if self.stopping.load(Ordering::Acquire) {
            self.logical.finish_request(&invocation.request_id);
            return Err(Error::new(ErrorKind::Backend, "function broker stopped"));
        }
        let (manifest, provider) = self.registry.resolve(
            &invocation.function_name,
            &invocation.function_version,
            &invocation.provider,
        )?;
        manifest.input_schema().validate(&invocation.input)?;
        let argument_bytes = invocation.input.canonical_bytes(Limits::default())?.len();
        if argument_bytes > self.settings.limits.max_argument_bytes {
            return Err(Error::limit());
        }
        // Result capacity is reserved before any physical effect, not after a response arrives.
        let reserved = argument_bytes
            .checked_add(self.settings.limits.max_result_bytes)
            .ok_or_else(Error::limit)?;
        let reservation = self.logical.reserve(&invocation.request_id, reserved)?;
        if self.stopping.load(Ordering::Acquire) {
            self.logical.finish_request(&invocation.request_id);
            return Err(Error::new(ErrorKind::Backend, "function broker stopped"));
        }
        let broker_deadline =
            Instant::now() + Duration::from_millis(self.settings.limits.call_timeout_ms);
        let deadline = caller_deadline.map_or(broker_deadline, |v| v.min(broker_deadline));
        let mut last = None;
        for attempt in 1..=self.settings.limits.max_attempts {
            if attempt > 1 {
                timeout_at(
                    deadline,
                    tokio::time::sleep(Duration::from_millis(10 * u64::from(attempt - 1))),
                )
                .await
                .map_err(|_| Error::new(ErrorKind::Deadline, "function call deadline"))?;
            }
            let permits = timeout_at(
                deadline,
                self.acquire(&invocation, provider.as_ref(), reserved),
            )
            .await
            .map_err(|_| Error::new(ErrorKind::Deadline, "function call deadline"))??;
            if cancellation.is_cancelled() || self.stopping.load(Ordering::Acquire) {
                return Err(Error::new(ErrorKind::Deadline, "function call cancelled"));
            }
            let attempt_cancellation = Cancellation::new();
            let physical = PhysicalRequest {
                logical_id: invocation.logical_id.clone(),
                attempt,
                input: invocation.input.clone(),
                max_result_bytes: self.settings.limits.max_result_bytes,
                deadline,
                cancellation: attempt_cancellation.clone(),
                manifest_binding: manifest_binding(&manifest),
            };
            let action = AuthorizationAction {
                session_id: &invocation.session_id,
                request_id: &invocation.request_id,
                logical_id: &invocation.logical_id,
                attempt,
                manifest: &manifest,
                provider: &provider.destination,
                argument_dependencies: &invocation.argument_dependencies,
                state_dependencies: &invocation.state_dependencies,
                fact_dependencies: &invocation.fact_dependencies,
                scope_dependencies: &invocation.scope_dependencies,
            };
            let adapter = provider.adapter.clone();
            // The future acquires the real native gate and performs only this bounded local
            // enqueue while guarded. Remote completion remains outside that gate.
            let physical = authorizer
                .authorize_and_enqueue(action, Box::new(move || adapter.enqueue(physical)))
                .await?;
            let (tx, rx) = oneshot::channel();
            let physical_reservation = reservation.clone();
            tokio::spawn(async move {
                let outcome = physical.finish().await;
                let _ = tx.send(outcome);
                // Permits and logical bytes remain owned until the adapter's actual future ends.
                drop((permits, physical_reservation));
            });
            let mut guard = AttemptCancellation(Some(attempt_cancellation));
            let outcome = tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    return Err(Error::new(ErrorKind::Deadline, "function call cancelled"));
                }
                value = timeout_at(deadline, rx) => match value {
                    Ok(Ok(v)) => v,
                    Ok(Err(_)) => Err(AttemptFailure {
                        class: FailureClass::Transport,
                        retryable: true,
                    }),
                    Err(_) => return Err(Error::new(ErrorKind::Deadline, "function call deadline")),
                }
            };
            guard.complete();
            match outcome {
                Ok(value) => {
                    manifest.output_schema().validate(&value)?;
                    return Ok(BrokerResult {
                        value,
                        manifest,
                        provider,
                        invocation,
                        attempt,
                        _reservation: reservation,
                    });
                }
                Err(failure) => {
                    let retry = failure.retryable
                        && manifest.retry_safe()
                        && attempt < self.settings.limits.max_attempts;
                    last = Some(failure);
                    if !retry {
                        break;
                    }
                }
            }
        }
        let mut failure = last.unwrap_or(AttemptFailure {
            class: FailureClass::Exhausted,
            retryable: false,
        });
        if failure.retryable {
            failure.class = FailureClass::Exhausted
        }
        Err(failure.error())
    }
    /// Stop admission for one trusted request after its controller has stopped spawning work.
    pub fn finish_request(&self, request_id: &str) {
        self.logical.finish_request(request_id);
    }

    pub fn settings(&self) -> &BrokerSettings {
        &self.settings
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Stops admission, cooperatively cancels/drains HTTP, and joins native adapters on
    /// blocking threads so shared Tokio workers are never occupied by native joins.
    pub async fn shutdown(&self) -> Result<()> {
        self.stopping.store(true, Ordering::Release);
        self.logical.stop_all();
        self.registry.shutdown().await
    }

    async fn acquire(
        &self,
        i: &Invocation,
        p: &registry::ProviderRegistration,
        bytes: usize,
    ) -> Result<(GatePermit, GatePermit, GatePermit)> {
        let global = self.global.acquire(&i.request_id, i.lane, bytes).await?;
        let group = self
            .groups
            .get(p.group.as_str())
            .ok_or_else(|| Error::invalid("provider group is not configured"))?
            .acquire(&i.request_id, i.lane, bytes)
            .await?;
        let provider = self
            .providers
            .get(p.id.as_str())
            .ok_or_else(|| Error::invalid("provider limits are not configured"))?
            .acquire(&i.request_id, i.lane, bytes)
            .await?;
        Ok((global, group, provider))
    }
}

struct AttemptCancellation(Option<Cancellation>);
impl AttemptCancellation {
    fn complete(&mut self) {
        self.0 = None;
    }
}
impl Drop for AttemptCancellation {
    fn drop(&mut self) {
        if let Some(cancellation) = self.0.take() {
            cancellation.cancel();
        }
    }
}

fn manifest_binding(
    manifest: &cdb_core::function_manifest::ExternalFunctionManifest,
) -> CanonicalValue {
    let implementation = manifest.implementation();
    let mut implementation_value = BTreeMap::new();
    implementation_value.insert(
        "build".into(),
        CanonicalValue::String(implementation.build.as_str().into()),
    );
    implementation_value.insert(
        "implementation".into(),
        CanonicalValue::String(implementation.implementation.as_str().into()),
    );
    implementation_value.insert(
        "model".into(),
        implementation
            .model
            .as_ref()
            .map_or(CanonicalValue::Null, |v| {
                CanonicalValue::String(v.as_str().into())
            }),
    );
    implementation_value.insert(
        "version".into(),
        CanonicalValue::String(implementation.version.as_str().into()),
    );
    let mut value = BTreeMap::new();
    value.insert(
        "artifact_hash".into(),
        CanonicalValue::String(manifest.artifact().hash().as_str().into()),
    );
    value.insert(
        "artifact_iri".into(),
        CanonicalValue::String(manifest.artifact().iri().as_str().into()),
    );
    value.insert(
        "artifact_version".into(),
        CanonicalValue::String(manifest.artifact().version().as_str().into()),
    );
    value.insert(
        "implementation".into(),
        CanonicalValue::Object(implementation_value),
    );
    value.insert(
        "name".into(),
        CanonicalValue::String(manifest.name().as_str().into()),
    );
    value.insert(
        "semantic_parameters".into(),
        manifest.semantic_parameters().clone(),
    );
    value.insert(
        "version".into(),
        CanonicalValue::String(manifest.version().as_str().into()),
    );
    CanonicalValue::Object(value)
}

/// Synchronous seam for the native Rhai callback. The service owns the runtime handle;
/// this adapter still requires an explicit authorizer and consumes the guarded result.
pub struct FunctionCallbackAdapter {
    pub broker: Arc<Broker>,
    pub runtime: tokio::runtime::Handle,
    pub authorizer: Arc<dyn TrustedAuthorizer>,
}
impl FunctionCallbackAdapter {
    pub fn call(&self, invocation: Invocation) -> Result<CanonicalValue> {
        self.runtime.block_on(async {
            self.broker
                .invoke(invocation, self.authorizer.clone())
                .await?
                .consume(self.authorizer.as_ref())
                .await
        })
    }
}
