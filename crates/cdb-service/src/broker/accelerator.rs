use super::{
    cpu::{NativeFunction, NativePool},
    dispatch::{Adapter, Attempt, ExecutionClass, PhysicalRequest},
};
use cdb_core::{
    function_manifest::{Batching, ExternalFunctionManifest},
    id::ContentHash,
    Error, Result,
};
use std::collections::BTreeMap;

/// Deterministic scheduler proof adapter. Its label is intentionally impossible to
/// confuse with production hardware availability.
pub struct TestAcceleratorAdapter {
    build: String,
    implementation: String,
    version: String,
    implementation_build: ContentHash,
    pool: NativePool,
}
impl TestAcceleratorAdapter {
    pub fn new_test_only(
        workers: usize,
        queue: usize,
        implementation: String,
        version: String,
        implementation_build: ContentHash,
        function: NativeFunction,
    ) -> Result<Self> {
        Ok(Self {
            build: "ctxql-test-accelerator/v1-NOT-REAL-HARDWARE".into(),
            implementation,
            version,
            implementation_build,
            pool: NativePool::new(workers, queue, "ctxql-test-accelerator", function)?,
        })
    }
}
impl Adapter for TestAcceleratorAdapter {
    fn class(&self) -> ExecutionClass {
        ExecutionClass::Accelerator
    }
    fn build_identity(&self) -> &str {
        &self.build
    }
    fn supports(&self, m: &ExternalFunctionManifest) -> bool {
        let i = m.implementation();
        i.implementation.as_str() == self.implementation
            && i.version.as_str() == self.version
            && i.build == self.implementation_build
            && i.model.is_none()
            && m.semantic_parameters()
                .as_object()
                .is_ok_and(BTreeMap::is_empty)
            && m.batching() == Batching::None
    }
    fn enqueue(&self, r: PhysicalRequest) -> Result<Attempt> {
        self.pool.enqueue(r)
    }
    fn shutdown(&self) -> Result<()> {
        self.pool.shutdown()
    }
}
impl Drop for TestAcceleratorAdapter {
    fn drop(&mut self) {
        let _ = self.pool.shutdown();
    }
}

pub fn unavailable_real_accelerator(_adapter_id: &str) -> Result<TestAcceleratorAdapter> {
    Err(Error::new(
        cdb_core::error::ErrorKind::Unsupported,
        "configured accelerator is not compiled and available",
    ))
}
