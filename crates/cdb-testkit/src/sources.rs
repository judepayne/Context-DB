//! Explicit immutable scripted providers; no filesystem, process, or provider fallback.
use cdb_core::{
    contracts::*, evidence::EvidenceSelector, id::*, source::*, CanonicalValue, Error, ErrorKind,
    Limits, Result,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
#[derive(Clone, Copy, Debug)]
pub struct SourceOptions {
    pub max_sources: usize,
    pub max_bytes: usize,
    pub max_scripts: usize,
}
impl Default for SourceOptions {
    fn default() -> Self {
        Self {
            max_sources: 1000,
            max_bytes: 8 * 1024 * 1024,
            max_scripts: 1000,
        }
    }
}
pub struct ImmutableSource {
    id: SourceId,
    version: ContentHash,
    bytes: Vec<u8>,
}
impl ImmutableSource {
    pub fn new(id: SourceId, bytes: Vec<u8>) -> Self {
        Self {
            id,
            version: ContentHash::of_bytes(&bytes),
            bytes,
        }
    }
    pub fn version(&self) -> &ContentHash {
        &self.version
    }
}
/// Private, issuer-bound and exact-selector-bound; only trusted fixture provisioning issues it.
pub struct SelectorAuthorization {
    issuer: Arc<()>,
    request: SourceReadRequest,
}
pub struct ScriptedSources {
    sources: Vec<ImmutableSource>,
    issuer: Arc<()>,
    fault: AtomicBool,
}
impl ScriptedSources {
    pub fn new(sources: Vec<ImmutableSource>, options: SourceOptions) -> Result<Self> {
        if options.max_sources == 0
            || options.max_bytes == 0
            || options.max_scripts == 0
            || sources.len() > options.max_sources
        {
            return Err(Error::limit());
        }
        let mut total = 0usize;
        let mut seen = std::collections::BTreeSet::new();
        for s in &sources {
            total = total.checked_add(s.bytes.len()).ok_or_else(Error::limit)?;
            if total > options.max_bytes {
                return Err(Error::limit());
            }
            if !seen.insert((s.id.clone(), s.version.clone())) {
                return Err(Error::invalid("duplicate configured source"));
            }
        }
        Ok(Self {
            sources,
            issuer: Arc::new(()),
            fault: AtomicBool::new(false),
        })
    }
    pub fn set_read_fault(&self, enabled: bool) {
        self.fault.store(enabled, Ordering::SeqCst);
    }
    pub fn authorize(&self, request: &SourceReadRequest) -> Result<SelectorAuthorization> {
        self.selected(request)?;
        Ok(SelectorAuthorization {
            issuer: self.issuer.clone(),
            request: request.clone(),
        })
    }
    fn selected(&self, request: &SourceReadRequest) -> Result<SourceRead> {
        if self.fault.load(Ordering::SeqCst) {
            return Err(Error::invalid("injected source read fault"));
        }
        let source = self
            .sources
            .iter()
            .find(|s| s.id == request.source_id && s.version == request.version)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "source version not configured"))?;
        let bytes = match request.selector {
            EvidenceSelector::WholeDocument => source.bytes.as_slice(),
            EvidenceSelector::Span(span) => span
                .select(
                    std::str::from_utf8(&source.bytes)
                        .map_err(|_| Error::invalid("source UTF-8"))?,
                )?
                .as_bytes(),
        };
        if bytes.len() > request.max_bytes {
            return Err(Error::limit());
        }
        SourceRead::from_request(request, bytes.to_vec())
    }
}
impl SourceReader for ScriptedSources {
    fn read<'a>(&'a self, request: &'a SourceReadRequest) -> IoFuture<'a, SourceRead> {
        Box::pin(async move { self.selected(request) })
    }

    fn read_reference<'a>(
        &'a self,
        source: &'a cdb_core::evidence::SourceReference,
        max_bytes: usize,
    ) -> IoFuture<'a, SourceRead> {
        Box::pin(async move {
            let request = SourceReadRequest {
                source_id: source.id().clone(),
                version: source
                    .version()
                    .cloned()
                    .ok_or_else(|| Error::invalid("source version"))?,
                selector: source
                    .selector()
                    .cloned()
                    .ok_or_else(|| Error::invalid("source selector"))?,
                max_bytes,
            };
            let configured = self
                .sources
                .iter()
                .find(|candidate| {
                    candidate.id == request.source_id && candidate.version == request.version
                })
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "source version not configured"))?;
            if source.verify(&configured.bytes)?
                != cdb_core::evidence::VerificationOutcome::Verified
            {
                return Err(Error::invalid("source evidence mismatch"));
            }
            self.selected(&request)
        })
    }
}
impl AuthorizedSelectorResolver for ScriptedSources {
    type Authorization = SelectorAuthorization;
    fn resolve<'a>(
        &'a self,
        auth: &'a SelectorAuthorization,
        request: &'a SourceReadRequest,
    ) -> IoFuture<'a, SourceRead> {
        Box::pin(async move {
            if !Arc::ptr_eq(&auth.issuer, &self.issuer)
                || auth.request.source_id != request.source_id
                || auth.request.version != request.version
                || auth.request.selector != request.selector
                || request.max_bytes > auth.request.max_bytes
            {
                return Err(Error::new(ErrorKind::Denied, "selector authorization"));
            }
            self.selected(request)
        })
    }
}
/// Matches every semantic request field, including exact selector, bytes and observation time.
pub struct ExtractionScript {
    pub request: ExtractionRequest,
    pub result: ExtractionResult,
}
pub struct ScriptedExtractor {
    scripts: Vec<ExtractionScript>,
    fault: AtomicBool,
}
impl ScriptedExtractor {
    pub fn new(scripts: Vec<ExtractionScript>, options: SourceOptions) -> Result<Self> {
        if options.max_sources == 0
            || options.max_scripts == 0
            || options.max_bytes == 0
            || scripts.len() > options.max_scripts
        {
            return Err(Error::limit());
        }
        let mut bytes = 0usize;
        for (i, script) in scripts.iter().enumerate() {
            if scripts[..i].iter().any(|s| {
                s.request.source == script.request.source
                    && s.request.extractor == script.request.extractor
                    && s.request.settings == script.request.settings
                    && s.request.observed_at == script.request.observed_at
            }) {
                return Err(Error::invalid("duplicate extraction script"));
            }
            bytes = bytes
                .checked_add(script.request.source.bytes().len())
                .ok_or_else(Error::limit)?;
            for v in [script.request.settings.clone(), output(&script.result)] {
                bytes = bytes
                    .checked_add(v.canonical_bytes(Limits::default())?.len())
                    .ok_or_else(Error::limit)?;
            }
            if bytes > options.max_bytes {
                return Err(Error::limit());
            }
        }
        Ok(Self {
            scripts,
            fault: AtomicBool::new(false),
        })
    }
    pub fn set_extract_fault(&self, enabled: bool) {
        self.fault.store(enabled, Ordering::SeqCst);
    }
}
fn output(result: &ExtractionResult) -> CanonicalValue {
    CanonicalValue::Array(vec![
        CanonicalValue::Array(result.candidates().iter().map(|c| c.projection()).collect()),
        result.provenance().clone(),
    ])
}
impl CandidateExtractor for ScriptedExtractor {
    fn extract<'a>(
        &'a self,
        request: &'a ExtractionRequest,
        limits: Limits,
    ) -> IoFuture<'a, ExtractionResult> {
        Box::pin(async move {
            if self.fault.load(Ordering::SeqCst) {
                return Err(Error::invalid("injected extraction fault"));
            }
            if request.source.bytes().len() > limits.input_bytes() {
                return Err(Error::limit());
            }
            let settings_bytes = request.settings.canonical_bytes(limits)?.len();
            if request
                .source
                .bytes()
                .len()
                .checked_add(settings_bytes)
                .ok_or_else(Error::limit)?
                > limits.input_bytes()
            {
                return Err(Error::limit());
            }
            let script = self
                .scripts
                .iter()
                .find(|s| {
                    s.request.source == request.source
                        && s.request.extractor == request.extractor
                        && s.request.settings == request.settings
                        && s.request.observed_at == request.observed_at
                })
                .ok_or_else(|| {
                    Error::new(ErrorKind::NotFound, "extractor script not configured")
                })?;
            if script.result.candidates().len() > request.max_candidates {
                return Err(Error::limit());
            }
            output(&script.result).canonical_bytes(limits)?;
            ExtractionResult::new(
                script.result.candidates().to_vec(),
                script.result.provenance().clone(),
                request.max_candidates,
            )
        })
    }
}
