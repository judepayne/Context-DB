use cdb_core::{Error, Limits, Result};
use std::collections::BTreeMap;

pub(crate) fn location(source: &[u8], offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut line_start = 0;
    let mut i = 0;
    while i < offset.min(source.len()) {
        if source[i] == b'\n' {
            line += 1;
            line_start = i + 1;
        } else if source[i] == b'\r' {
            line += 1;
            if source.get(i + 1) == Some(&b'\n') {
                i += 1;
            }
            line_start = i + 1;
        }
        i += 1;
    }
    (line, offset.saturating_sub(line_start) + 1)
}

/// Half-open UTF-8 byte offsets in the original artifact (including its BOM).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
}
#[derive(Clone, Debug)]
pub struct SourceMap {
    pub spans: BTreeMap<String, SourceSpan>,
    line_starts: Vec<usize>,
    source_len: usize,
    retained: usize,
}
impl SourceMap {
    pub(crate) fn new(source: &str, limits: Limits) -> Result<Self> {
        let mut line_starts = vec![0];
        let b = source.as_bytes();
        for (i, byte) in b.iter().enumerate() {
            if *byte == b'\n' || (*byte == b'\r' && b.get(i + 1) != Some(&b'\n')) {
                if line_starts.len() >= limits.values() {
                    return Err(Error::limit());
                }
                line_starts.push(i + 1);
            }
        }
        let retained = line_starts
            .len()
            .checked_mul(std::mem::size_of::<usize>())
            .ok_or_else(Error::limit)?;
        if retained > limits.output_bytes() {
            return Err(Error::limit());
        }
        Ok(Self {
            spans: BTreeMap::new(),
            line_starts,
            source_len: source.len(),
            retained,
        })
    }
    pub(crate) fn insert(&mut self, path: &str, span: SourceSpan, limits: Limits) -> Result<()> {
        if self.spans.len() >= limits.values() {
            return Err(Error::limit());
        }
        self.retained = self
            .retained
            .checked_add(path.len() + std::mem::size_of::<SourceSpan>())
            .ok_or_else(Error::limit)?;
        if self.retained > limits.output_bytes() {
            return Err(Error::limit());
        }
        self.spans.insert(path.to_owned(), span);
        Ok(())
    }
    /// One-based logical line and byte column; CRLF is one line break.
    pub fn location(&self, offset: usize) -> Option<(usize, usize)> {
        if offset > self.source_len {
            return None;
        }
        let line = self
            .line_starts
            .partition_point(|start| *start <= offset)
            .saturating_sub(1);
        Some((line + 1, offset - self.line_starts[line] + 1))
    }
    pub fn exact_span(&self, path: &str) -> Option<SourceSpan> {
        self.spans.get(path).copied()
    }
    /// Find the nearest mapped structural ancestor of a JSON pointer.
    pub fn span(&self, path: &str) -> Option<SourceSpan> {
        let mut path = path;
        loop {
            if let Some(span) = self.spans.get(path) {
                return Some(*span);
            }
            path = path.rsplit_once('/')?.0;
        }
    }
}

impl SourceMap {
    pub(crate) fn map_json(
        &mut self,
        text: &str,
        base: usize,
        value: &cdb_core::CanonicalValue,
        limits: Limits,
    ) -> Result<()> {
        fn ws(b: &[u8], pos: &mut usize) {
            while b.get(*pos).is_some_and(u8::is_ascii_whitespace) {
                *pos += 1;
            }
        }
        fn string_end(b: &[u8], pos: &mut usize) {
            *pos += 1;
            while *pos < b.len() {
                let c = b[*pos];
                *pos += 1;
                if c == 92 {
                    *pos += 1;
                } else if c == b'"' {
                    break;
                }
            }
        }
        #[allow(clippy::too_many_arguments)]
        fn walk(
            map: &mut SourceMap,
            text: &str,
            base: usize,
            pos: &mut usize,
            value: &cdb_core::CanonicalValue,
            path: &str,
            limits: Limits,
        ) -> Result<()> {
            use cdb_core::CanonicalValue as V;
            let b = text.as_bytes();
            ws(b, pos);
            let start = *pos;
            match value {
                V::Object(o) => {
                    *pos += 1;
                    ws(b, pos);
                    for index in 0..o.len() {
                        if index > 0 {
                            *pos += 1;
                            ws(b, pos);
                        }
                        let ks = *pos;
                        string_end(b, pos);
                        let key = V::parse(&b[ks..*pos], limits)?;
                        let key = key.as_str()?;
                        ws(b, pos);
                        *pos += 1;
                        let child =
                            format!("{}/{}", path, key.replace('~', "~0").replace('/', "~1"));
                        walk(map, text, base, pos, &o[key], &child, limits)?;
                        ws(b, pos);
                    }
                    *pos += 1;
                }
                V::Array(a) => {
                    *pos += 1;
                    ws(b, pos);
                    for (index, v) in a.iter().enumerate() {
                        if index > 0 {
                            *pos += 1;
                        }
                        walk(map, text, base, pos, v, &format!("{path}/{index}"), limits)?;
                        ws(b, pos);
                    }
                    *pos += 1;
                }
                V::String(_) => string_end(b, pos),
                _ => {
                    while b.get(*pos).is_some_and(|c| {
                        !c.is_ascii_whitespace() && !matches!(c, b',' | b']' | b'}')
                    }) {
                        *pos += 1;
                    }
                }
            }
            map.insert(
                path,
                SourceSpan {
                    start: base + start,
                    end: base + *pos,
                },
                limits,
            )
        }
        walk(self, text, base, &mut 0, value, "", limits)
    }
}
