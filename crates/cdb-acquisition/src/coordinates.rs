use cdb_core::evidence::Utf8Span;
use cdb_core::id::{ContentHash, Iri};
use cdb_core::{Error, Result};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LineId(String);
impl LineId {
    /// Parse only an opaque ID previously issued by a host coordinate map.
    pub fn from_host(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        ContentHash::parse(&value)?;
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineRow {
    pub id: LineId,
    pub document_span: Utf8Span,
    pub line_number: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinateMap {
    attempt_id: String,
    window_id: String,
    locator: Iri,
    text_version: ContentHash,
    text_object: ContentHash,
    window: Utf8Span,
    lines: Vec<LineRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LineSelection {
    WholeLine,
    Range { start: usize, end: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineCoordinate {
    pub line_id: LineId,
    pub selection: LineSelection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedSpan {
    pub span: Utf8Span,
    pub selected_hash: ContentHash,
    pub line_start: usize,
    pub line_end: usize,
}

impl CoordinateMap {
    pub fn issue(
        document: &str,
        attempt_id: &str,
        window_id: &str,
        locator: Iri,
        text_version: ContentHash,
        text_object: ContentHash,
        window: Utf8Span,
    ) -> Result<Self> {
        validate_token(attempt_id)?;
        validate_token(window_id)?;
        window.select(document)?;
        if window.start() == window.end() {
            return Err(Error::invalid("empty window"));
        }
        let mut lines = Vec::new();
        let mut line_start = 0usize;
        let mut line_number = 1usize;
        for segment in document.split_inclusive('\n') {
            let line_end = line_start + segment.len();
            let start = line_start.max(window.start());
            let end = line_end.min(window.end());
            if start < end {
                lines.push(LineRow {
                    id: opaque_line_id(attempt_id, window_id, lines.len()),
                    document_span: Utf8Span::new(start, end)?,
                    line_number,
                });
            }
            line_start = line_end;
            line_number += 1;
        }
        if line_start < document.len() {
            let start = line_start.max(window.start());
            let end = document.len().min(window.end());
            if start < end {
                lines.push(LineRow {
                    id: opaque_line_id(attempt_id, window_id, lines.len()),
                    document_span: Utf8Span::new(start, end)?,
                    line_number,
                });
            }
        }
        if lines.is_empty() {
            return Err(Error::invalid("window has no visible lines"));
        }
        Ok(Self {
            attempt_id: attempt_id.to_owned(),
            window_id: window_id.to_owned(),
            locator,
            text_version,
            text_object,
            window,
            lines,
        })
    }

    pub fn lines(&self) -> &[LineRow] {
        &self.lines
    }
    pub fn locator(&self) -> &Iri {
        &self.locator
    }
    pub fn text_version(&self) -> &ContentHash {
        &self.text_version
    }
    pub fn text_object(&self) -> &ContentHash {
        &self.text_object
    }

    /// Host-issued range handles accepted by the v2 proposal protocol. The
    /// window handle permits an exact quote to span line boundaries; line
    /// handles remain available for compact prompts and legacy compatibility.
    pub fn issued_ranges(&self) -> Vec<String> {
        let mut ranges = Vec::with_capacity(self.lines.len() + 1);
        ranges.push(self.window_range_id());
        ranges.extend(self.lines.iter().map(|line| line.id.as_str().to_owned()));
        ranges
    }

    pub fn window_range_id(&self) -> String {
        ContentHash::of_bytes(
            format!(
                "ctxql-range-map/v2\0{}\0{}\0{}\0{}",
                self.attempt_id,
                self.window_id,
                self.window.start(),
                self.window.end()
            )
            .as_bytes(),
        )
        .as_str()
        .to_owned()
    }

    /// Resolve an exact occurrence without repairing or normalizing source
    /// bytes. `occurrence` is zero-based among exact, non-overlapping matches
    /// within the host-issued range.
    pub fn resolve_quote(
        &self,
        document: &str,
        range: &str,
        quote: &str,
        occurrence: usize,
    ) -> Result<ResolvedSpan> {
        if quote.is_empty() || ContentHash::of_bytes(document.as_bytes()) != self.text_object {
            return Err(Error::invalid("invalid evidence quote or retained text"));
        }
        let base = if range == self.window_range_id() {
            self.window
        } else {
            self.lines
                .iter()
                .find(|line| line.id.as_str() == range)
                .map(|line| line.document_span)
                .ok_or_else(|| Error::invalid("unknown range handle"))?
        };
        let text = base.select(document)?;
        let relative_start = text
            .match_indices(quote)
            .nth(occurrence)
            .map(|(start, _)| start)
            .ok_or_else(|| Error::invalid("exact evidence occurrence not found"))?;
        let start = base
            .start()
            .checked_add(relative_start)
            .ok_or_else(Error::limit)?;
        let end = start.checked_add(quote.len()).ok_or_else(Error::limit)?;
        let span = Utf8Span::new(start, end)?;
        if span.end() > base.end() || span.select(document)? != quote {
            return Err(Error::invalid("evidence quote mismatch"));
        }
        let line_start = 1 + document[..start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let line_end = line_start + quote.bytes().filter(|byte| *byte == b'\n').count();
        Ok(ResolvedSpan {
            span,
            selected_hash: ContentHash::of_bytes(quote.as_bytes()),
            line_start,
            line_end,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resolve(
        &self,
        document: &str,
        attempt_id: &str,
        window_id: &str,
        locator: &Iri,
        text_version: &ContentHash,
        coordinates: &[LineCoordinate],
        max_spans: usize,
    ) -> Result<Vec<ResolvedSpan>> {
        if attempt_id != self.attempt_id || window_id != self.window_id {
            return Err(Error::invalid("coordinate map scope mismatch"));
        }
        if locator != &self.locator || text_version != &self.text_version {
            return Err(Error::invalid("source identity mismatch"));
        }
        if ContentHash::of_bytes(document.as_bytes()) != self.text_object {
            return Err(Error::invalid("retained text object mismatch"));
        }
        if coordinates.is_empty() || coordinates.len() > max_spans {
            return Err(Error::limit());
        }
        let mut out = Vec::with_capacity(coordinates.len());
        let mut previous_end = None;
        for coordinate in coordinates {
            let row = self
                .lines
                .iter()
                .find(|r| r.id == coordinate.line_id)
                .ok_or_else(|| Error::invalid("unknown line ID"))?;
            let line = row.document_span.select(document)?;
            let relative = match coordinate.selection {
                LineSelection::WholeLine => Utf8Span::new(0, line.len())?,
                LineSelection::Range { start, end } => Utf8Span::new(start, end)?,
            };
            if relative.start() == relative.end() {
                return Err(Error::invalid("empty source span"));
            }
            let selected = relative.select(line)?;
            let start = row
                .document_span
                .start()
                .checked_add(relative.start())
                .ok_or_else(Error::limit)?;
            let end = row
                .document_span
                .start()
                .checked_add(relative.end())
                .ok_or_else(Error::limit)?;
            let span = Utf8Span::new(start, end)?;
            if span.start() < self.window.start() || span.end() > self.window.end() {
                return Err(Error::invalid("span outside window"));
            }
            if previous_end.is_some_and(|last| span.start() < last) {
                return Err(Error::invalid("spans not ordered or overlap"));
            }
            previous_end = Some(span.end());
            out.push(ResolvedSpan {
                span,
                selected_hash: ContentHash::of_bytes(selected.as_bytes()),
                line_start: row.line_number,
                line_end: row.line_number,
            });
        }
        Ok(out)
    }
}

fn validate_token(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err(Error::invalid("bounded coordinate scope ID required"))
    } else {
        Ok(())
    }
}

fn opaque_line_id(attempt: &str, window: &str, ordinal: usize) -> LineId {
    let commitment = format!("ctxql-line-map/v1\0{attempt}\0{window}\0{ordinal}");
    LineId(
        ContentHash::of_bytes(commitment.as_bytes())
            .as_str()
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(text: &str) -> CoordinateMap {
        CoordinateMap::issue(
            text,
            "attempt",
            "window",
            Iri::new("file:///doc.txt").unwrap(),
            ContentHash::of_bytes(b"converter-bound-text-version"),
            ContentHash::of_bytes(text.as_bytes()),
            Utf8Span::new(0, text.len()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn resolves_exact_utf8_ranges_and_hashes() {
        let text = "αbeta\r\nsecond\n";
        let map = map(text);
        let spans = map
            .resolve(
                text,
                "attempt",
                "window",
                map.locator(),
                map.text_version(),
                &[LineCoordinate {
                    line_id: map.lines()[0].id.clone(),
                    selection: LineSelection::Range { start: 2, end: 6 },
                }],
                2,
            )
            .unwrap();
        assert_eq!(spans[0].span.select(text).unwrap(), "beta");
        assert_eq!(spans[0].selected_hash, ContentHash::of_bytes(b"beta"));
        assert_eq!(spans[0].line_start, 1);
    }

    #[test]
    fn resolves_multiline_and_repeated_v2_evidence_without_normalization() {
        let text = "Borrower α\nand Borrower α\n";
        let map = map(text);
        let range = map.window_range_id();
        let second = map.resolve_quote(text, &range, "Borrower α", 1).unwrap();
        assert_eq!(second.span.select(text).unwrap(), "Borrower α");
        assert_eq!(second.line_start, 2);
        let multiline = map
            .resolve_quote(text, &range, "Borrower α\nand Borrower", 0)
            .unwrap();
        assert_eq!(multiline.line_start, 1);
        assert_eq!(multiline.line_end, 2);
        assert!(map.resolve_quote(text, &range, "Borrower a", 0).is_err());
        assert!(map.resolve_quote(text, &range, "Borrower α", 2).is_err());
    }

    #[test]
    fn rejects_utf8_interior_stale_identity_and_empty_or_unordered_spans() {
        let text = "αx\ny\n";
        let map = map(text);
        let bad = |selection| {
            map.resolve(
                text,
                "attempt",
                "window",
                map.locator(),
                map.text_version(),
                &[LineCoordinate {
                    line_id: map.lines()[0].id.clone(),
                    selection,
                }],
                2,
            )
        };
        assert!(bad(LineSelection::Range { start: 1, end: 2 }).is_err());
        assert!(bad(LineSelection::Range { start: 2, end: 2 }).is_err());
        assert!(map
            .resolve(
                text,
                "other",
                "window",
                map.locator(),
                map.text_version(),
                &[LineCoordinate {
                    line_id: map.lines()[0].id.clone(),
                    selection: LineSelection::WholeLine
                }],
                2
            )
            .is_err());
        let reversed = vec![
            LineCoordinate {
                line_id: map.lines()[1].id.clone(),
                selection: LineSelection::WholeLine,
            },
            LineCoordinate {
                line_id: map.lines()[0].id.clone(),
                selection: LineSelection::WholeLine,
            },
        ];
        assert!(map
            .resolve(
                text,
                "attempt",
                "window",
                map.locator(),
                map.text_version(),
                &reversed,
                2
            )
            .is_err());
    }

    #[test]
    fn does_not_normalize_or_search_quotes() {
        let text = "a\r\nb\n";
        let map = map(text);
        let span = map
            .resolve(
                text,
                "attempt",
                "window",
                map.locator(),
                map.text_version(),
                &[LineCoordinate {
                    line_id: map.lines()[0].id.clone(),
                    selection: LineSelection::WholeLine,
                }],
                1,
            )
            .unwrap();
        assert_eq!(span[0].span.select(text).unwrap(), "a\r\n");
        let normalized = "a\nb\n";
        assert!(map
            .resolve(
                normalized,
                "attempt",
                "window",
                map.locator(),
                map.text_version(),
                &[LineCoordinate {
                    line_id: map.lines()[0].id.clone(),
                    selection: LineSelection::WholeLine
                }],
                1
            )
            .is_err());
    }
}
