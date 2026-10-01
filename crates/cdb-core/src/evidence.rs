use crate::id::*;
use crate::value::obj;
use crate::{CanonicalValue as V, Error, Result};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Utf8Span {
    start: usize,
    end: usize,
}
impl Utf8Span {
    pub fn new(start: usize, end: usize) -> Result<Self> {
        if start > end {
            return Err(Error::invalid("reversed span"));
        }
        Ok(Self { start, end })
    }
    pub fn start(self) -> usize {
        self.start
    }
    pub fn end(self) -> usize {
        self.end
    }
    pub fn select(self, text: &str) -> Result<&str> {
        text.get(self.start..self.end)
            .ok_or_else(|| Error::invalid("UTF-8 span bounds"))
    }
    pub fn from_scalars(text: &str, start: usize, end: usize) -> Result<Self> {
        if start > end {
            return Err(Error::invalid("scalar span"));
        }
        let mut offsets = text
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(text.len()));
        let a = offsets
            .nth(start)
            .ok_or_else(|| Error::invalid("scalar start"))?;
        let b = if end == start {
            a
        } else {
            offsets
                .nth(end - start - 1)
                .ok_or_else(|| Error::invalid("scalar end"))?
        };
        Self::new(a, b)
    }
    pub fn from_chunk(text: &str, chunk: Self, relative: Self) -> Result<Self> {
        let part = chunk.select(text)?;
        relative.select(part)?;
        Self::new(
            chunk
                .start
                .checked_add(relative.start)
                .ok_or_else(Error::limit)?,
            chunk
                .start
                .checked_add(relative.end)
                .ok_or_else(Error::limit)?,
        )
    }
    pub fn projection(self) -> V {
        obj([
            ("start", V::integer(self.start as u64)),
            ("end", V::integer(self.end as u64)),
        ])
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceSelector {
    WholeDocument,
    Span(Utf8Span),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceReference {
    wire: V,
    id: SourceId,
    version: Option<ContentHash>,
    selector: Option<EvidenceSelector>,
    content_hash: Option<ContentHash>,
    object_hash: Option<ContentHash>,
}
impl SourceReference {
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(
            &["source_id", "kind"],
            &[
                "uri",
                "version",
                "fragment_id",
                "selectors",
                "content_hash",
                "object_hash",
            ],
        )?;
        let o = v.as_object()?;
        let id = SourceId::new(v.field("source_id")?.as_str()?)?;
        ResourceId::new(v.field("kind")?.as_str()?)?;
        if let Some(x) = o.get("uri") {
            Iri::new(x.as_str()?)?;
        }
        if let Some(x) = o.get("fragment_id") {
            FragmentId::new(x.as_str()?)?;
        }
        let version = o
            .get("version")
            .map(|v| ContentHash::parse(v.as_str()?))
            .transpose()?;
        let content_hash = o
            .get("content_hash")
            .map(|v| ContentHash::parse(v.as_str()?))
            .transpose()?;
        let object_hash = o
            .get("object_hash")
            .map(|v| ContentHash::parse(v.as_str()?))
            .transpose()?;
        let selector = o.get("selectors").map(validate_selectors).transpose()?;
        let p6_text = v.field("kind")?.as_str()? == "ctxql.source.extraction-text";
        if object_hash.is_some() != p6_text
            || p6_text
                && (version.is_none()
                    || content_hash.is_none()
                    || !matches!(selector, Some(EvidenceSelector::Span(_))))
        {
            return Err(Error::invalid("source object identity scope"));
        }
        Ok(Self {
            wire: v.clone(),
            id,
            version,
            selector,
            content_hash,
            object_hash,
        })
    }
    pub fn id(&self) -> &SourceId {
        &self.id
    }
    pub fn version(&self) -> Option<&ContentHash> {
        self.version.as_ref()
    }
    pub fn selector(&self) -> Option<&EvidenceSelector> {
        self.selector.as_ref()
    }
    pub fn content_hash(&self) -> Option<&ContentHash> {
        self.content_hash.as_ref()
    }
    pub fn has_span(&self) -> bool {
        matches!(self.selector, Some(EvidenceSelector::Span(_)))
    }
    pub fn projection(&self) -> V {
        self.wire.clone()
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<VerificationOutcome> {
        let Some(version) = &self.version else {
            return Ok(VerificationOutcome::Unverifiable);
        };
        let retained_identity = self.object_hash.as_ref().unwrap_or(version);
        if &ContentHash::of_bytes(bytes) != retained_identity {
            return Ok(VerificationOutcome::Changed);
        }
        let selected = match &self.selector {
            Some(EvidenceSelector::WholeDocument) => bytes,
            Some(EvidenceSelector::Span(span)) => {
                let text =
                    std::str::from_utf8(bytes).map_err(|_| Error::invalid("source UTF-8"))?;
                let selected = span.select(text)?;
                let selectors = self.wire.field("selectors")?;
                if let Some(q) = selectors.as_object()?.get("text_quote") {
                    if q.field("exact")?.as_str()? != selected {
                        return Err(Error::invalid("exact quote mismatch"));
                    }
                    if let Some(p) = q.as_object()?.get("prefix") {
                        if !text[..span.start].ends_with(p.as_str()?) {
                            return Err(Error::invalid("quote prefix"));
                        }
                    }
                    if let Some(s) = q.as_object()?.get("suffix") {
                        if !text[span.end..].starts_with(s.as_str()?) {
                            return Err(Error::invalid("quote suffix"));
                        }
                    }
                }
                if let Some(line) = selectors.as_object()?.get("line") {
                    let start = text[..span.start].bytes().filter(|b| *b == b'\n').count() + 1;
                    let last = if span.end > span.start {
                        span.end - 1
                    } else {
                        span.end
                    };
                    let end = text.as_bytes()[..last]
                        .iter()
                        .filter(|b| **b == b'\n')
                        .count()
                        + 1;
                    if line.field("start")?.u64()? != start as u64
                        || line.field("end")?.u64()? != end as u64
                    {
                        return Err(Error::invalid("contradictory line selector"));
                    }
                }
                selected.as_bytes()
            }
            None => return Ok(VerificationOutcome::Unverifiable),
        };
        Ok(match &self.content_hash {
            None => VerificationOutcome::Unverifiable,
            Some(h) if *h == ContentHash::of_bytes(selected) => VerificationOutcome::Verified,
            Some(_) => VerificationOutcome::Changed,
        })
    }
}
pub fn validate_selectors(v: &V) -> Result<EvidenceSelector> {
    v.closed(
        &["contract"],
        &["utf8", "whole_document", "page", "line", "text_quote"],
    )?;
    if v.field("contract")?.as_str()? != "ctxql-evidence/v1" {
        return Err(Error::invalid("selector contract"));
    }
    let o = v.as_object()?;
    let selector = match (o.get("utf8"), o.get("whole_document")) {
        (Some(s), None) => {
            s.closed(&["start", "end"], &[])?;
            EvidenceSelector::Span(Utf8Span::new(
                usize::try_from(s.field("start")?.u64()?).map_err(|_| Error::limit())?,
                usize::try_from(s.field("end")?.u64()?).map_err(|_| Error::limit())?,
            )?)
        }
        (None, Some(V::Bool(true))) => EvidenceSelector::WholeDocument,
        _ => return Err(Error::invalid("exactly one explicit selector")),
    };
    if matches!(selector, EvidenceSelector::WholeDocument)
        && o.keys()
            .any(|k| matches!(k.as_str(), "page" | "line" | "text_quote"))
    {
        return Err(Error::invalid("whole/span contradiction"));
    }
    if let Some(p) = o.get("page") {
        if p.u64()? == 0 {
            return Err(Error::invalid("page is one based"));
        }
    }
    if let Some(l) = o.get("line") {
        l.closed(&["start", "end"], &[])?;
        let a = l.field("start")?.u64()?;
        if a == 0 || a > l.field("end")?.u64()? {
            return Err(Error::invalid("line interval"));
        }
    }
    if let Some(q) = o.get("text_quote") {
        q.closed(&["exact"], &["prefix", "suffix"])?;
        for v in q.as_object()?.values() {
            v.as_str()?;
        }
    }
    Ok(selector)
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lineage {
    sources: Vec<SourceReference>,
}
impl Lineage {
    pub fn empty() -> Self {
        Self { sources: vec![] }
    }
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(&["schema", "sources"], &[])?;
        if v.field("schema")?.as_str()? != "ctxql.lineage.v1" {
            return Err(Error::invalid("lineage schema"));
        }
        Ok(Self {
            sources: v
                .field("sources")?
                .as_array()?
                .iter()
                .map(SourceReference::from_value)
                .collect::<Result<_>>()?,
        })
    }
    pub fn sources(&self) -> &[SourceReference] {
        &self.sources
    }
    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql.lineage.v1")),
            (
                "sources",
                V::Array(
                    self.sources
                        .iter()
                        .map(SourceReference::projection)
                        .collect(),
                ),
            ),
        ])
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationOutcome {
    Verified,
    Unverifiable,
    Missing,
    Changed,
    Denied,
    NotRequested,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceVerification {
    pub source_id: SourceId,
    pub version: Option<ContentHash>,
    pub fragment_id: Option<FragmentId>,
    pub outcome: VerificationOutcome,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversionProvenance(V);
impl ConversionProvenance {
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(
            &[
                "original_source_id",
                "original_version",
                "original_content_hash",
                "text_source_id",
                "text_version",
                "converter",
                "converter_version",
                "arguments",
                "encoding",
                "normalization",
            ],
            &[],
        )?;
        for k in ["original_source_id", "text_source_id"] {
            SourceId::new(v.field(k)?.as_str()?)?;
        }
        for k in ["original_version", "original_content_hash", "text_version"] {
            ContentHash::parse(v.field(k)?.as_str()?)?;
        }
        for k in [
            "converter",
            "converter_version",
            "encoding",
            "normalization",
        ] {
            ResourceId::new(v.field(k)?.as_str()?)?;
        }
        for arg in v.field("arguments")?.as_array()? {
            arg.as_str()?;
        }
        if v.field("encoding")?.as_str()? != "UTF-8" {
            return Err(Error::invalid("conversion encoding"));
        }
        Ok(Self(v.clone()))
    }
    pub fn projection(&self) -> V {
        self.0.clone()
    }
}
