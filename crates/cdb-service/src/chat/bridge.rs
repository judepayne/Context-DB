use super::ChatReadResources;
use cdb_provider_pi::ontology_bridge::{OntologyToolError, OntologyToolHost, ToolCapability};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

const MAX_CALL_ID_BYTES: usize = 256;
const MAX_EARLY_CANCELLATIONS: usize = 40;

#[derive(Debug)]
enum CallState {
    CancelledBeforeInvoke {
        cancellation: Arc<AtomicBool>,
        epoch: u64,
    },
    Active {
        cancellation: Arc<AtomicBool>,
        generation: u64,
    },
    Completed,
}

#[derive(Debug)]
struct CallRegistry {
    calls: BTreeMap<String, CallState>,
    accepting: bool,
    epoch: u64,
    next_generation: u64,
    real_calls: usize,
    early_cancellations: usize,
    max_real_calls: usize,
}

impl CallRegistry {
    fn new(max_real_calls: usize) -> Self {
        Self {
            calls: BTreeMap::new(),
            accepting: false,
            epoch: 0,
            next_generation: 1,
            real_calls: 0,
            early_cancellations: 0,
            max_real_calls,
        }
    }

    fn begin_turn(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
        self.accepting = true;
    }

    fn reserve(&mut self, call_id: &str) -> Result<(Arc<AtomicBool>, u64), OntologyToolError> {
        if !self.accepting
            || call_id.is_empty()
            || call_id.len() > MAX_CALL_ID_BYTES
            || self.real_calls >= self.max_real_calls
        {
            return Err(OntologyToolError::Denied);
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);
        let cancellation = match self.calls.get(call_id) {
            None => Arc::new(AtomicBool::new(false)),
            Some(CallState::CancelledBeforeInvoke {
                cancellation,
                epoch,
            }) if *epoch == self.epoch => {
                self.early_cancellations = self.early_cancellations.saturating_sub(1);
                cancellation.clone()
            }
            Some(
                CallState::CancelledBeforeInvoke { .. }
                | CallState::Active { .. }
                | CallState::Completed,
            ) => return Err(OntologyToolError::Denied),
        };
        self.calls.insert(
            call_id.to_owned(),
            CallState::Active {
                cancellation: cancellation.clone(),
                generation,
            },
        );
        self.real_calls += 1;
        Ok((cancellation, generation))
    }

    fn complete(&mut self, call_id: &str, generation: u64) {
        if matches!(
            self.calls.get(call_id),
            Some(CallState::Active { generation: current, .. }) if *current == generation
        ) {
            self.calls.insert(call_id.to_owned(), CallState::Completed);
        }
    }

    fn cancel(&mut self, call_id: &str) -> Result<(), OntologyToolError> {
        if call_id.is_empty() || call_id.len() > MAX_CALL_ID_BYTES {
            return Err(OntologyToolError::Denied);
        }
        match self.calls.get(call_id) {
            Some(CallState::Active { cancellation, .. })
            | Some(CallState::CancelledBeforeInvoke { cancellation, .. }) => {
                cancellation.store(true, Ordering::Release);
                Ok(())
            }
            Some(CallState::Completed) => Ok(()),
            None if !self.accepting => Ok(()),
            None if self.early_cancellations >= MAX_EARLY_CANCELLATIONS => {
                Err(OntologyToolError::Denied)
            }
            None => {
                let cancellation = Arc::new(AtomicBool::new(true));
                self.calls.insert(
                    call_id.to_owned(),
                    CallState::CancelledBeforeInvoke {
                        cancellation,
                        epoch: self.epoch,
                    },
                );
                self.early_cancellations += 1;
                Ok(())
            }
        }
    }

    fn end_turn(&mut self) {
        self.accepting = false;
        for state in self.calls.values() {
            if let CallState::Active { cancellation, .. }
            | CallState::CancelledBeforeInvoke { cancellation, .. } = state
            {
                cancellation.store(true, Ordering::Release);
            }
        }
    }
}

/// Synchronous bridge adapter used only from the provider's OS bridge workers.
/// Every accepted invocation receives a bounded, non-reusable cancellation
/// slot which is threaded through protected read queues and native operations.
pub(crate) struct ChatToolHost {
    resources: Arc<ChatReadResources>,
    runtime: tokio::runtime::Handle,
    calls: Mutex<CallRegistry>,
    legacy_id: AtomicU64,
}

impl ChatToolHost {
    pub(crate) fn new(
        resources: Arc<ChatReadResources>,
        runtime: tokio::runtime::Handle,
        max_calls: usize,
    ) -> Self {
        Self {
            resources,
            runtime,
            calls: Mutex::new(CallRegistry::new(max_calls)),
            legacy_id: AtomicU64::new(1),
        }
    }

    pub(crate) fn begin_turn(&self) {
        self.calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .begin_turn();
    }

    pub(crate) fn end_turn(&self) {
        self.calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .end_turn();
    }

    pub(crate) fn cancel_all(&self) {
        self.end_turn();
    }

    fn dispatch(
        &self,
        call_id: &str,
        tool: &str,
        request: &Value,
    ) -> Result<Value, OntologyToolError> {
        let (cancellation, generation) = self
            .calls
            .lock()
            .map_err(|_| OntologyToolError::Denied)?
            .reserve(call_id)?;
        let bytes = serde_json::to_vec(request).map_err(|_| OntologyToolError::Denied)?;
        let result =
            self.runtime
                .block_on(self.resources.dispatch_tool(tool, &bytes, cancellation));
        if let Ok(mut calls) = self.calls.lock() {
            calls.complete(call_id, generation);
        }
        result.map_err(|_| OntologyToolError::Denied)
    }
}

impl OntologyToolHost for ChatToolHost {
    fn lookup(&self, request: &Value) -> Result<Value, OntologyToolError> {
        let id = self.legacy_id.fetch_add(1, Ordering::Relaxed);
        self.dispatch(&format!("legacy-ontology-{id}"), "ctxql_ontology", request)
    }

    fn invoke(
        &self,
        capability: ToolCapability,
        call_id: &str,
        request: &Value,
    ) -> Result<Value, OntologyToolError> {
        let tool = tool_name(capability).ok_or(OntologyToolError::Denied)?;
        self.dispatch(call_id, tool, request)
    }

    fn cancel(&self, call_id: &str) -> Result<(), OntologyToolError> {
        self.calls
            .lock()
            .map_err(|_| OntologyToolError::Denied)?
            .cancel(call_id)
    }
}

fn tool_name(capability: ToolCapability) -> Option<&'static str> {
    match capability {
        ToolCapability::Capabilities => Some("ctxql_capabilities"),
        ToolCapability::Ontology => Some("ctxql_ontology"),
        ToolCapability::GraphQuery => Some("ctxql_graph_query"),
        ToolCapability::Source => Some("ctxql_source"),
        ToolCapability::Entities | ToolCapability::GraphPlayground => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_capabilities_are_closed_before_dispatch() {
        assert_eq!(tool_name(ToolCapability::GraphPlayground), None);
        assert_eq!(tool_name(ToolCapability::Entities), None);
        assert_eq!(
            tool_name(ToolCapability::GraphQuery),
            Some("ctxql_graph_query")
        );
    }

    #[test]
    fn registry_rejects_duplicate_and_never_reuses_completed_id() {
        let mut registry = CallRegistry::new(2);
        registry.begin_turn();
        let (_, generation) = registry.reserve("call-1").unwrap();
        assert!(registry.reserve("call-1").is_err());
        registry.complete("call-1", generation);
        registry.end_turn();
        registry.begin_turn();
        assert!(registry.reserve("call-1").is_err());
    }

    #[test]
    fn cancel_before_invoke_is_bounded_and_reaches_the_real_call() {
        let mut registry = CallRegistry::new(1);
        registry.begin_turn();
        registry.cancel("early").unwrap();
        let (cancellation, generation) = registry.reserve("early").unwrap();
        assert!(cancellation.load(Ordering::Acquire));
        registry.complete("early", generation);
        assert!(registry.reserve("another").is_err());

        let mut bounded = CallRegistry::new(1);
        bounded.begin_turn();
        for index in 0..MAX_EARLY_CANCELLATIONS {
            bounded.cancel(&format!("unknown-{index}")).unwrap();
        }
        assert!(bounded.cancel("one-too-many").is_err());

        let mut stale = CallRegistry::new(1);
        stale.begin_turn();
        stale.cancel("old").unwrap();
        stale.end_turn();
        stale.begin_turn();
        assert!(stale.reserve("old").is_err());
    }

    #[test]
    fn end_turn_closes_gate_and_cancels_active_calls() {
        let mut registry = CallRegistry::new(2);
        registry.begin_turn();
        let (cancellation, _) = registry.reserve("active").unwrap();
        registry.end_turn();
        assert!(cancellation.load(Ordering::Acquire));
        assert!(registry.reserve("late").is_err());
        assert!(registry.cancel("unknown-after-turn").is_ok());
    }
}
