use crate::cancel::CancellationToken;
use crate::parser::{parse_output, ParseLimits, ParsedOutput};
use crate::transport::{PiTransport, TransportError};
use crate::usage::Usage;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub enum ProviderError {
    Transport(TransportError),
    Grammar(crate::parser::ParseError),
}
impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Grammar(e) => write!(f, "grammar: {e}"),
        }
    }
}
impl std::error::Error for ProviderError {}

/// Thin composition: transport returns transient text; parser immediately closes it into candidates.
pub struct PiProvider {
    transport: PiTransport,
    parse_limits: ParseLimits,
}

#[derive(Debug)]
pub struct WindowOutcome {
    pub window_id: String,
    pub output: Result<ParsedOutput, ProviderError>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedResponse {
    pub phase: &'static str,
    pub window_ids: Vec<String>,
    pub text: Option<String>,
    pub parse_error: Option<crate::parser::ParseError>,
    pub transport_error: Option<TransportError>,
}
impl PiProvider {
    pub fn new(transport: PiTransport, parse_limits: ParseLimits) -> Self {
        Self {
            transport,
            parse_limits,
        }
    }
    pub fn extract(
        &self,
        request: &str,
        window_ids: &[String],
        cancel: &CancellationToken,
    ) -> Result<ParsedOutput, ProviderError> {
        let reply = self
            .transport
            .request(request, cancel)
            .map_err(ProviderError::Transport)?;
        parse_output(&reply.text, window_ids, &self.parse_limits).map_err(ProviderError::Grammar)
    }
    /// Try a same-document batch of at most two windows, then immediately retry
    /// failed or unowned windows once as individuals. Successfully parsed batch
    /// siblings are retained in memory and are never called again.
    pub fn extract_batch_with_fallback(
        &self,
        batch_request: &str,
        individual_requests: &[(String, String)],
        cancel: &CancellationToken,
    ) -> Vec<WindowOutcome> {
        self.extract_batch_with_fallback_captured(batch_request, individual_requests, cancel)
            .0
    }

    pub fn extract_batch_with_fallback_captured(
        &self,
        batch_request: &str,
        individual_requests: &[(String, String)],
        cancel: &CancellationToken,
    ) -> (Vec<WindowOutcome>, Vec<CapturedResponse>) {
        if individual_requests.is_empty() || individual_requests.len() > 2 {
            return (
                individual_requests
                    .iter()
                    .map(|(window_id, _)| WindowOutcome {
                        window_id: window_id.clone(),
                        output: Err(ProviderError::Grammar(crate::parser::ParseError::Limit(
                            "batch_windows",
                        ))),
                    })
                    .collect(),
                Vec::new(),
            );
        }
        let ids: Vec<String> = individual_requests
            .iter()
            .map(|(id, _)| id.clone())
            .collect();
        if ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
            return (
                individual_requests
                    .iter()
                    .map(|(window_id, _)| WindowOutcome {
                        window_id: window_id.clone(),
                        output: Err(ProviderError::Grammar(
                            crate::parser::ParseError::CrossWindowAmbiguity,
                        )),
                    })
                    .collect(),
                Vec::new(),
            );
        }

        let mut captured = Vec::new();
        let mut retained = BTreeMap::new();
        match self.transport.request(batch_request, cancel) {
            Ok(reply) => {
                let parsed = parse_output(&reply.text, &ids, &self.parse_limits);
                captured.push(CapturedResponse {
                    phase: "batch",
                    window_ids: ids.clone(),
                    text: Some(reply.text),
                    parse_error: parsed.as_ref().err().cloned(),
                    transport_error: None,
                });
                match parsed {
                    Ok(ParsedOutput::Claims(pairs)) => {
                        let mut by_window: BTreeMap<String, Vec<_>> = BTreeMap::new();
                        for pair in pairs {
                            by_window
                                .entry(pair.claim.window_id.clone())
                                .or_default()
                                .push(pair);
                        }
                        for (window_id, pairs) in by_window {
                            retained.insert(window_id, ParsedOutput::Claims(pairs));
                        }
                    }
                    Ok(no_claims @ ParsedOutput::NoClaims { .. }) if ids.len() == 1 => {
                        retained.insert(ids[0].clone(), no_claims);
                    }
                    Ok(ParsedOutput::NoClaims { .. }) | Err(_) => {}
                }
            }
            Err(error) => captured.push(CapturedResponse {
                phase: "batch",
                window_ids: ids.clone(),
                text: None,
                parse_error: None,
                transport_error: Some(error),
            }),
        }

        let outcomes = individual_requests
            .iter()
            .map(|(window_id, request)| {
                let output = if let Some(output) = retained.remove(window_id) {
                    Ok(output)
                } else {
                    match self.transport.request(request, cancel) {
                        Ok(reply) => {
                            let parsed = parse_output(
                                &reply.text,
                                std::slice::from_ref(window_id),
                                &self.parse_limits,
                            );
                            captured.push(CapturedResponse {
                                phase: "individual",
                                window_ids: vec![window_id.clone()],
                                text: Some(reply.text),
                                parse_error: parsed.as_ref().err().cloned(),
                                transport_error: None,
                            });
                            parsed.map_err(ProviderError::Grammar)
                        }
                        Err(error) => {
                            captured.push(CapturedResponse {
                                phase: "individual",
                                window_ids: vec![window_id.clone()],
                                text: None,
                                parse_error: None,
                                transport_error: Some(error.clone()),
                            });
                            Err(ProviderError::Transport(error))
                        }
                    }
                };
                WindowOutcome {
                    window_id: window_id.clone(),
                    output,
                }
            })
            .collect();
        (outcomes, captured)
    }

    pub fn usage(&self) -> Usage {
        self.transport.usage()
    }
    pub fn teardown(&self) {
        self.transport.teardown();
    }
}
