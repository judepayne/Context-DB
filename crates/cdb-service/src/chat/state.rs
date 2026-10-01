use crate::config::ChatLimits;
use cdb_core::{evidence::SourceReference, Error, ErrorKind, Limits, Result};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone)]
pub(crate) struct SourceCitation {
    pub epoch: u64,
    pub reference: SourceReference,
}

#[derive(Clone)]
struct ClaimCitation {
    token: String,
    metadata: Vec<u8>,
}

#[derive(Clone)]
struct RetainedGraph {
    id: String,
    encoded: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct ChatState {
    limits: ChatLimits,
    epoch: u64,
    revision: u64,
    next_result: u64,
    next_claim: u64,
    next_source: u64,
    tools: usize,
    queries: usize,
    turn_tools: usize,
    turn_queries: usize,
    turn_source_bytes: usize,
    turn_response_bytes: usize,
    graphs: VecDeque<RetainedGraph>,
    sources: BTreeMap<String, SourceCitation>,
    source_bindings: BTreeMap<Vec<u8>, String>,
    claim_bindings: BTreeMap<Vec<u8>, ClaimCitation>,
    query_log: Vec<(String, String)>,
    retained_bytes: usize,
    inventory_cursor: Option<Vec<u8>>,
}

impl ChatState {
    pub(crate) fn new(limits: ChatLimits) -> Self {
        Self {
            limits,
            epoch: 1,
            revision: 1,
            next_result: 1,
            next_claim: 1,
            next_source: 1,
            tools: 0,
            queries: 0,
            turn_tools: 0,
            turn_queries: 0,
            turn_source_bytes: 0,
            turn_response_bytes: 0,
            graphs: VecDeque::new(),
            sources: BTreeMap::new(),
            source_bindings: BTreeMap::new(),
            claim_bindings: BTreeMap::new(),
            query_log: Vec::new(),
            retained_bytes: 0,
            inventory_cursor: None,
        }
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn begin_turn(&mut self) {
        for (query, outcome) in self.query_log.drain(..) {
            self.retained_bytes = self
                .retained_bytes
                .saturating_sub(query.len() + outcome.len());
        }
        self.turn_tools = 0;
        self.turn_queries = 0;
        self.turn_source_bytes = 0;
        self.turn_response_bytes = 0;
        self.revision = self.revision.saturating_add(1);
    }

    pub(crate) fn clear_epoch(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
        self.revision = self.revision.saturating_add(1);
        self.graphs.clear();
        self.sources.clear();
        self.source_bindings.clear();
        self.claim_bindings.clear();
        self.query_log.clear();
        self.inventory_cursor = None;
        self.retained_bytes = 0;
    }

    /// One active inventory chain per session. The position is not caller-chosen;
    /// a cursor is useful only after a successful, fenced preceding page.
    pub(crate) fn validate_inventory_cursor(&self, cursor: Option<&[u8]>) -> Result<()> {
        if cursor.is_some() && cursor != self.inventory_cursor.as_deref() {
            return Err(Error::invalid(
                "inventory cursor was not issued or is no longer current",
            ));
        }
        Ok(())
    }

    pub(crate) fn set_inventory_cursor(&mut self, cursor: Option<Vec<u8>>) -> Result<()> {
        let retained = self
            .retained_bytes
            .saturating_sub(self.inventory_cursor.as_ref().map_or(0, Vec::len))
            .checked_add(cursor.as_ref().map_or(0, Vec::len))
            .ok_or_else(Error::limit)?;
        if retained > self.limits.max_state_bytes {
            return Err(Error::limit());
        }
        self.retained_bytes = retained;
        self.inventory_cursor = cursor;
        Ok(())
    }

    pub(crate) fn reserve_tool(&mut self, query: bool) -> Result<()> {
        if self.tools >= self.limits.max_tool_calls
            || self.turn_tools >= self.limits.max_tool_calls_per_turn
            || query
                && (self.queries >= self.limits.max_queries
                    || self.turn_queries >= self.limits.max_queries_per_turn)
        {
            return Err(Error::limit());
        }
        self.tools += 1;
        self.turn_tools += 1;
        if query {
            self.queries += 1;
            self.turn_queries += 1;
        }
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    pub(crate) fn reserve_response(&mut self, bytes: usize) -> Result<()> {
        if bytes > self.limits.max_response_bytes
            || self.turn_response_bytes.saturating_add(bytes)
                > self.limits.max_tool_response_bytes_per_turn
        {
            return Err(Error::limit());
        }
        self.turn_response_bytes += bytes;
        Ok(())
    }

    pub(crate) fn reserve_source_bytes(&mut self, bytes: usize) -> Result<()> {
        if bytes > self.limits.max_source_span_bytes
            || self.turn_source_bytes.saturating_add(bytes) > self.limits.max_source_bytes_per_turn
        {
            return Err(Error::limit());
        }
        self.turn_source_bytes += bytes;
        Ok(())
    }

    pub(crate) fn issue_result(&mut self) -> (String, Option<String>) {
        let id = format!("R{}-E{}", self.next_result, self.epoch);
        self.next_result = self.next_result.saturating_add(1);
        let evicted = if self.graphs.len() >= self.limits.max_live_graphs {
            self.graphs.pop_front().map(|graph| {
                self.retained_bytes = self.retained_bytes.saturating_sub(graph.encoded.len());
                graph.id
            })
        } else {
            None
        };
        (id, evicted)
    }

    pub(crate) fn retain_graph(&mut self, id: String, encoded: Vec<u8>) -> Result<()> {
        self.charge(encoded.len())?;
        self.graphs.push_back(RetainedGraph { id, encoded });
        Ok(())
    }

    pub(crate) fn issue_claim(&mut self, binding: Vec<u8>, metadata: Vec<u8>) -> Result<String> {
        if let Some(citation) = self.claim_bindings.get(&binding) {
            return Ok(citation.token.clone());
        }
        if self.claim_bindings.len().saturating_add(self.sources.len()) >= self.limits.max_citations
        {
            return Err(Error::limit());
        }
        let token = format!("[C{}]", self.next_claim);
        self.next_claim = self.next_claim.saturating_add(1);
        self.charge(
            binding
                .len()
                .saturating_add(token.len())
                .saturating_add(metadata.len()),
        )?;
        self.claim_bindings.insert(
            binding,
            ClaimCitation {
                token: token.clone(),
                metadata,
            },
        );
        Ok(token)
    }

    pub(crate) fn issue_source(&mut self, reference: SourceReference) -> Result<String> {
        let binding = reference.projection().canonical_bytes(Limits::default())?;
        if let Some(key) = self.source_bindings.get(&binding) {
            return Ok(format!("[{key}]"));
        }
        if self.claim_bindings.len().saturating_add(self.sources.len()) >= self.limits.max_citations
        {
            return Err(Error::limit());
        }
        let key = format!("S{}", self.next_source);
        self.next_source = self.next_source.saturating_add(1);
        self.charge(key.len().saturating_add(binding.len()))?;
        self.sources.insert(
            key.clone(),
            SourceCitation {
                epoch: self.epoch,
                reference,
            },
        );
        self.source_bindings.insert(binding, key.clone());
        Ok(format!("[{key}]"))
    }

    pub(crate) fn source(&self, key: &str) -> Result<SourceReference> {
        let normalized = key
            .strip_prefix('[')
            .and_then(|v| v.strip_suffix(']'))
            .unwrap_or(key);
        self.sources
            .get(normalized)
            .filter(|citation| citation.epoch == self.epoch)
            .map(|citation| citation.reference.clone())
            .ok_or_else(|| Error::new(ErrorKind::Denied, "source reference unavailable"))
    }

    pub(crate) fn log_query(&mut self, query: &str, outcome: &str) -> Result<()> {
        let bytes = query.len().saturating_add(outcome.len());
        self.charge(bytes)?;
        self.query_log.push((query.to_owned(), outcome.to_owned()));
        Ok(())
    }

    pub(crate) fn queries(&self) -> Vec<(String, String)> {
        self.query_log.clone()
    }

    /// Resolves metadata already obtained in this epoch, not a new protected
    /// graph/source read. Never treats the token as authority to fetch content.
    pub(crate) fn citation(&self, token: &str) -> Option<serde_json::Value> {
        if let Some(claim) = self
            .claim_bindings
            .values()
            .find(|claim| claim.token == token)
        {
            let metadata: serde_json::Value = serde_json::from_slice(&claim.metadata).ok()?;
            return Some(
                serde_json::json!({"kind":"claim", "claim_id":metadata.get("claim_id")?, "metadata":metadata}),
            );
        }
        let key = token.strip_prefix('[')?.strip_suffix(']')?;
        let source = self
            .sources
            .get(key)
            .filter(|source| source.epoch == self.epoch)?;
        let reference = source
            .reference
            .projection()
            .canonical_bytes(Limits::default())
            .ok()?;
        let reference: serde_json::Value = serde_json::from_slice(&reference).ok()?;
        Some(
            serde_json::json!({"kind":"source", "source_id":reference.get("source_id")?,
            "version":reference.get("version"), "selectors":reference.get("selectors"), "reference":reference}),
        )
    }

    fn charge(&mut self, bytes: usize) -> Result<()> {
        let next = self
            .retained_bytes
            .checked_add(bytes)
            .ok_or_else(Error::limit)?;
        if next > self.limits.max_state_bytes {
            return Err(Error::limit());
        }
        self.retained_bytes = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdb_core::CanonicalValue as V;

    #[test]
    fn inventory_cursor_is_exact_session_state_and_byte_accounted() {
        let mut state = ChatState::new(ChatLimits {
            max_state_bytes: 8,
            ..ChatLimits::default()
        });
        assert!(state.validate_inventory_cursor(Some(b"issued")).is_err());
        state
            .set_inventory_cursor(Some(b"issued".to_vec()))
            .unwrap();
        assert_eq!(state.retained_bytes, 6);
        assert!(state.validate_inventory_cursor(Some(b"forged")).is_err());
        state.begin_turn();
        state.validate_inventory_cursor(Some(b"issued")).unwrap();
        assert!(state.set_inventory_cursor(Some(vec![0; 9])).is_err());
        state.validate_inventory_cursor(Some(b"issued")).unwrap();
        state.set_inventory_cursor(Some(b"next".to_vec())).unwrap();
        assert_eq!(state.retained_bytes, 4);
        assert!(state.validate_inventory_cursor(Some(b"issued")).is_err());
        state.clear_epoch();
        assert_eq!(state.retained_bytes, 0);
        assert!(state.validate_inventory_cursor(Some(b"next")).is_err());
    }

    fn reference() -> SourceReference {
        SourceReference::from_value(
            &V::parse(
                br#"{"source_id":"urn:ctxql:source:text:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kind":"ctxql.source.extraction-text","version":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","object_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","content_hash":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","selectors":{"contract":"ctxql-evidence/v1","utf8":{"start":0,"end":1},"line":{"start":1,"end":1},"text_quote":{"exact":"x"}}}"#,
                Limits::default(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn eviction_keeps_exact_citation_bindings_but_epoch_invalidates_sources() {
        let limits = ChatLimits {
            max_live_graphs: 2,
            ..ChatLimits::default()
        };
        let mut state = ChatState::new(limits);
        let (r1, _) = state.issue_result();
        state.retain_graph(r1, vec![0; 20]).unwrap();
        let (r2, _) = state.issue_result();
        state.retain_graph(r2, vec![0; 20]).unwrap();
        let (r3, evicted) = state.issue_result();
        assert_eq!(evicted, Some("R1-E1".into()));
        state.retain_graph(r3, vec![0; 20]).unwrap();
        let first_claim = state
            .issue_claim(b"snapshot\0claim".to_vec(), vec![0; 10])
            .unwrap();
        assert_eq!(
            state
                .issue_claim(b"snapshot\0claim".to_vec(), vec![0; 10])
                .unwrap(),
            first_claim
        );
        let first = state.issue_source(reference()).unwrap();
        assert_eq!(state.issue_source(reference()).unwrap(), first);
        assert!(state.source(&first).is_ok());
        state.clear_epoch();
        assert!(state.source(&first).is_err());
        assert_ne!(state.issue_source(reference()).unwrap(), first);
        assert_eq!(state.issue_result().0, "R4-E2");
    }

    #[test]
    fn local_inspection_uses_only_issued_metadata_and_last_turn_queries() {
        let mut state = ChatState::new(ChatLimits::default());
        let claim = state
            .issue_claim(
                b"exact snapshot binding".to_vec(),
                br#"{"claim_id":"urn:claim:one","relation":"urn:relation:one"}"#.to_vec(),
            )
            .unwrap();
        assert_eq!(state.citation(&claim).unwrap()["claim_id"], "urn:claim:one");
        assert_eq!(
            state.citation(&claim).unwrap()["metadata"]["claim_id"],
            "urn:claim:one"
        );
        assert_eq!(
            state.citation(&claim).unwrap()["metadata"]["relation"],
            "urn:relation:one"
        );
        assert!(state.citation("[C999]").is_none());
        let source = state.issue_source(reference()).unwrap();
        assert_eq!(
            state.citation(&source).unwrap()["selectors"]["text_quote"]["exact"],
            "x"
        );
        state.log_query("exact query", "complete:R1-E1").unwrap();
        assert_eq!(
            state.queries(),
            vec![("exact query".into(), "complete:R1-E1".into())]
        );
        state.begin_turn();
        assert!(state.queries().is_empty());
        assert!(state.citation(&claim).is_some());
        state.clear_epoch();
        assert!(state.citation(&claim).is_none());
        assert!(state.citation(&source).is_none());
    }

    #[test]
    fn failed_calls_are_reserved_and_turn_budgets_reset_separately() {
        let limits = ChatLimits {
            max_tool_calls_per_turn: 1,
            ..ChatLimits::default()
        };
        let mut state = ChatState::new(limits);
        state.reserve_tool(false).unwrap();
        assert!(state.reserve_tool(false).is_err());
        state.begin_turn();
        state.reserve_tool(false).unwrap();
    }
}
