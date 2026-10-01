use super::*;
use crate::broker::{
    dispatch::{Adapter, Attempt, ExecutionClass},
    permissions::{AuthorizationAction, AuthorizationFuture, GuardedEnqueue},
    registry::ProviderRegistration,
};
use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    function_manifest::ExternalFunctionManifest,
    id::{ContentHash, Iri, ResourceId, VersionId},
};
use std::collections::BTreeSet;
use tokio::sync::Semaphore;

const BYTES: &[u8] = br#"{"schema":"ctxql-external-function/v1","name":"held","version":"1","implementation":{"implementation":"urn:test:held","version":"1","build":"sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f","model":null},"input_schema":{"type":"null"},"output_schema":{"type":"null"},"semantic_parameters":{},"capabilities":[],"declarations":{"deterministic":true,"order_independent":true,"retry_safe":false,"batching":"none"}}"#;

struct Allow;
impl TrustedAuthorizer for Allow {
    fn authorize_and_enqueue<'a>(
        &'a self,
        _action: AuthorizationAction<'a>,
        enqueue: Box<dyn GuardedEnqueue>,
    ) -> AuthorizationFuture<'a, Attempt> {
        Box::pin(async move { enqueue.enqueue() })
    }
    fn authorize_result<'a>(
        &'a self,
        _action: AuthorizationAction<'a>,
        _result: &'a CanonicalValue,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}
struct HeldAdapter {
    release: Arc<Semaphore>,
}
impl Adapter for HeldAdapter {
    fn class(&self) -> ExecutionClass {
        ExecutionClass::CpuBlocking
    }
    fn build_identity(&self) -> &str {
        "held-test/v1"
    }
    fn supports(&self, _: &ExternalFunctionManifest) -> bool {
        true
    }
    fn enqueue(&self, _: PhysicalRequest) -> Result<Attempt> {
        let release = self.release.clone();
        Ok(Attempt(Box::pin(async move {
            let permit = release.acquire_owned().await.map_err(|_| AttemptFailure {
                class: FailureClass::Unavailable,
                retryable: false,
            })?;
            permit.forget();
            Ok(CanonicalValue::Null)
        })))
    }
}
fn invocation() -> Invocation {
    Invocation {
        session_id: "s".into(),
        request_id: "r".into(),
        logical_id: "l".into(),
        lane: 0,
        function_name: "held".into(),
        function_version: "1".into(),
        provider: "p".into(),
        argument_dependencies: vec![],
        state_dependencies: vec![],
        fact_dependencies: vec![],
        scope_dependencies: vec![],
        input: CanonicalValue::Null,
    }
}
#[tokio::test]
async fn timed_out_native_attempt_retains_logical_and_physical_capacity_until_return() {
    let reference = ArtifactRef::new(
        Iri::new("urn:test:held-manifest").unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(BYTES),
    );
    let artifact = PublishedArtifact::new(reference, BYTES.to_vec(), Limits::default()).unwrap();
    let manifest = ExternalFunctionManifest::from_published(&artifact, Limits::default()).unwrap();
    let release = Arc::new(Semaphore::new(0));
    let resource = ResourceLimits {
        max_in_flight: 1,
        max_queued_bytes: 2 * 1024 * 1024,
        requests_per_second: 1000,
        burst_requests: 10,
    };
    let provider = ProviderRegistration {
        id: ResourceId::new("p").unwrap(),
        destination: ResourceId::new("d").unwrap(),
        group: ResourceId::new("g").unwrap(),
        limits: resource,
        allowed_manifests: BTreeSet::from([ProviderRegistration::binding(manifest.artifact())]),
        adapter: Arc::new(HeldAdapter {
            release: release.clone(),
        }),
    };
    let registry = Registry::new(vec![manifest], vec![provider]).unwrap();
    let limits = BrokerLimits {
        call_timeout_ms: 20,
        per_request_pending: 1,
        max_attempts: 1,
        ..Default::default()
    };
    let broker = Broker::new(
        registry,
        BrokerSettings {
            enabled: true,
            limits,
            groups: BTreeMap::from([("g".into(), resource)]),
        },
        &BTreeMap::from([("p".into(), resource)]),
    )
    .unwrap();
    let authorizer: Arc<dyn TrustedAuthorizer> = Arc::new(Allow);
    let error = match broker.invoke(invocation(), authorizer.clone()).await {
        Ok(_) => panic!("timed-out native call succeeded"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Deadline);
    let error = match broker.invoke(invocation(), authorizer.clone()).await {
        Ok(_) => panic!("capacity released before native return"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Limit);
    release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(probe) = broker.logical.reserve("r", 1) {
                drop(probe);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    broker.finish_request("r");
}
