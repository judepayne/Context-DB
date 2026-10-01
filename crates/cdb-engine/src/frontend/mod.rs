//! Lossless query/profile frontend. Published bytes are never rewritten.
mod parser;
mod source_map;
mod structure;
use crate::artifacts::ArtifactKind;
use cdb_core::{CanonicalValue, Error, Limits, Result};
pub use source_map::{SourceMap, SourceSpan};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceRole {
    Query,
    Profile,
    Config,
}
impl SourceRole {
    pub fn for_kind(kind: ArtifactKind) -> Self {
        match kind {
            ArtifactKind::Query => Self::Query,
            ArtifactKind::Profile => Self::Profile,
            ArtifactKind::Config => Self::Config,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub source_role: SourceRole,
    pub span: SourceSpan,
    pub line: usize,
    pub column: usize,
}

/// Structured parse failure for callers that need source diagnostics. The
/// original `parse` API remains available and returns the embedded core error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseError {
    pub error: Error,
    pub diagnostic: Diagnostic,
}
impl ParseError {
    pub fn into_error(self) -> Error {
        self.error
    }
}
#[derive(Clone, Debug)]
pub struct ParsedDocument {
    pub value: CanonicalValue,
    pub source_map: SourceMap,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn parse(kind: ArtifactKind, bytes: &[u8], limits: Limits) -> Result<ParsedDocument> {
    let document = parse_syntax(kind, bytes, limits)?;
    if kind != ArtifactKind::Config {
        structure::validate(&document.value, kind == ArtifactKind::Profile)?;
    }
    Ok(document)
}

/// Shared bounded language recognition and syntax parsing without semantic
/// artifact-shape validation. Catalogs retain their P4 role as byte registries.
pub fn parse_syntax(kind: ArtifactKind, bytes: &[u8], limits: Limits) -> Result<ParsedDocument> {
    parse_detailed(kind, bytes, limits).map_err(ParseError::into_error)
}

pub fn parse_detailed(
    kind: ArtifactKind,
    bytes: &[u8],
    limits: Limits,
) -> std::result::Result<ParsedDocument, ParseError> {
    parse_inner(kind, bytes, limits).map_err(|error| {
        let source = std::str::from_utf8(bytes).unwrap_or("");
        let offset = source
            .char_indices()
            .find(|(_, c)| !c.is_whitespace() && *c != '\u{feff}')
            .map_or(0, |(i, _)| i);
        let end = source[offset..]
            .chars()
            .next()
            .map_or(offset, |c| offset + c.len_utf8());
        let (line, column) = source_map::location(source.as_bytes(), offset);
        ParseError {
            diagnostic: Diagnostic {
                code: match error.kind {
                    cdb_core::ErrorKind::Limit => "source_limit",
                    _ => "source_syntax",
                },
                source_role: SourceRole::for_kind(kind),
                span: SourceSpan { start: offset, end },
                line,
                column,
            },
            error,
        }
    })
}

fn parse_inner(kind: ArtifactKind, bytes: &[u8], limits: Limits) -> Result<ParsedDocument> {
    if bytes.len() > limits.input_bytes() || bytes.len() > limits.work() {
        return Err(Error::limit());
    }
    let source = std::str::from_utf8(bytes).map_err(|_| Error::invalid("UTF-8"))?;
    let start = usize::from(source.starts_with('\u{feff}')) * 3;
    let text = &source[start..];
    let mut source_map = SourceMap::new(source, limits)?;
    // Anything other than an exact text header remains strict JSON, including
    // malformed JSON. Comments before a text header never affect JSON parsing.
    let header = text
        .split(['\r', '\n'])
        .map(str::trim)
        .find(|s| !s.is_empty() && !s.starts_with('#') && !s.starts_with("//"));
    let text_mode = kind != ArtifactKind::Config && matches!(header, Some("QUERY" | "PROFILE"));
    let value = if text_mode {
        parser::parse(kind, text, start, limits, &mut source_map)?
    } else {
        let value = CanonicalValue::parse(text.as_bytes(), limits)?;
        source_map.map_json(text, start, &value, limits)?;
        value
    };
    // Apply aggregate value/depth/output budgets to the constructed document,
    // not merely independently to each literal.
    fn count(
        v: &CanonicalValue,
        depth: usize,
        n: &mut usize,
        size: &mut usize,
        l: Limits,
    ) -> Result<()> {
        *n = n.checked_add(1).ok_or_else(Error::limit)?;
        if *n > l.values() || depth > l.depth() {
            return Err(Error::limit());
        }
        match v {
            CanonicalValue::String(s) => {
                *size = size.checked_add(s.len()).ok_or_else(Error::limit)?
            }
            CanonicalValue::Array(a) => {
                for v in a {
                    count(v, depth + 1, n, size, l)?;
                }
            }
            CanonicalValue::Object(o) => {
                for (k, v) in o {
                    *size = size.checked_add(k.len()).ok_or_else(Error::limit)?;
                    count(v, depth + 1, n, size, l)?;
                }
            }
            _ => *size = size.checked_add(1).ok_or_else(Error::limit)?,
        }
        if *size > l.output_bytes() {
            return Err(Error::limit());
        }
        Ok(())
    }
    count(&value, 0, &mut 0, &mut 0, limits)?;
    Ok(ParsedDocument {
        value,
        source_map,
        diagnostics: Vec::new(),
    })
}
