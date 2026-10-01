use super::{dispatch::Adapter, limits::ResourceLimits};
use cdb_core::{
    artifact::ArtifactRef, function_manifest::ExternalFunctionManifest, id::ResourceId, Error,
    Result,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub struct ProviderRegistration {
    pub id: ResourceId,
    pub destination: ResourceId,
    pub group: ResourceId,
    pub limits: ResourceLimits,
    /// Immutable exact artifact allowlist. Registration is not a disclosure grant.
    pub allowed_manifests: BTreeSet<(String, String, String)>,
    pub adapter: Arc<dyn Adapter>,
}
impl ProviderRegistration {
    pub fn binding(reference: &ArtifactRef) -> (String, String, String) {
        (
            reference.iri().as_str().into(),
            reference.version().as_str().into(),
            reference.hash().as_str().into(),
        )
    }
    pub fn permits(&self, manifest: &ExternalFunctionManifest) -> bool {
        self.allowed_manifests
            .contains(&Self::binding(manifest.artifact()))
    }
}

pub struct Registry {
    manifests: BTreeMap<(String, String), Arc<ExternalFunctionManifest>>,
    providers: BTreeMap<String, Arc<ProviderRegistration>>,
}
impl Registry {
    pub fn new(
        manifests: Vec<ExternalFunctionManifest>,
        providers: Vec<ProviderRegistration>,
    ) -> Result<Self> {
        let mut m = BTreeMap::new();
        for manifest in manifests {
            let key = (
                manifest.name().as_str().into(),
                manifest.version().as_str().into(),
            );
            if m.insert(key, Arc::new(manifest)).is_some() {
                return Err(Error::invalid("duplicate function manifest"));
            }
        }
        let mut p = BTreeMap::new();
        for provider in providers {
            if provider.allowed_manifests.is_empty() {
                return Err(Error::invalid("empty provider manifest allowlist"));
            }
            if provider.adapter.build_identity().is_empty() {
                return Err(Error::invalid("empty adapter build identity"));
            }
            if p.insert(provider.id.as_str().into(), Arc::new(provider))
                .is_some()
            {
                return Err(Error::invalid("duplicate provider"));
            }
        }
        for provider in p.values() {
            for binding in &provider.allowed_manifests {
                let manifest = m
                    .values()
                    .find(|x| ProviderRegistration::binding(x.artifact()) == *binding)
                    .ok_or_else(|| {
                        Error::invalid("provider allowlist references unknown exact manifest")
                    })?;
                if !provider.adapter.supports(manifest) {
                    return Err(Error::invalid(
                        "adapter cannot bind exact manifest implementation",
                    ));
                }
            }
        }
        Ok(Self {
            manifests: m,
            providers: p,
        })
    }
    pub fn manifest(&self, name: &str, version: &str) -> Option<Arc<ExternalFunctionManifest>> {
        self.manifests.get(&(name.into(), version.into())).cloned()
    }
    pub fn provider(&self, id: &str) -> Option<Arc<ProviderRegistration>> {
        self.providers.get(id).cloned()
    }
    pub fn resolve(
        &self,
        name: &str,
        version: &str,
        provider: &str,
    ) -> Result<(Arc<ExternalFunctionManifest>, Arc<ProviderRegistration>)> {
        let manifest = self
            .manifests
            .get(&(name.into(), version.into()))
            .cloned()
            .ok_or_else(|| Error::invalid("function is not registered"))?;
        let provider = self
            .providers
            .get(provider)
            .cloned()
            .ok_or_else(|| Error::invalid("provider is not registered"))?;
        if !provider.permits(&manifest) {
            return Err(Error::invalid("exact manifest/provider binding denied"));
        }
        Ok((manifest, provider))
    }

    pub async fn shutdown(&self) -> Result<()> {
        let mut adapters: Vec<Arc<dyn Adapter>> = Vec::new();
        for provider in self.providers.values() {
            if !adapters
                .iter()
                .any(|adapter| Arc::ptr_eq(adapter, &provider.adapter))
            {
                adapters.push(provider.adapter.clone());
            }
        }
        let mut joins = Vec::with_capacity(adapters.len());
        for adapter in adapters {
            joins.push(tokio::task::spawn_blocking(move || adapter.shutdown()));
        }
        let mut first_error = None;
        for join in joins {
            match join.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) if first_error.is_none() => first_error = Some(error),
                Err(_) if first_error.is_none() => {
                    first_error = Some(Error::invalid("adapter shutdown task failed"));
                }
                Ok(Err(_)) | Err(_) => {}
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}
