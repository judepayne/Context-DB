use crate::coordinates::ResolvedSpan;
use cdb_core::evidence::Lineage;
use cdb_core::id::{ContentHash, Iri, SourceId};
use cdb_core::{CanonicalValue as V, Error, Result};

fn obj<const N: usize>(fields: [(&str, V); N]) -> V {
    V::object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value)),
    )
    .expect("static object keys are unique")
}

/// Constructs strict P6 lineage over the existing v1 wire representation.
/// Every source reference has one explicit nonempty UTF-8 selector and never a
/// quote selector or whole-document special case.
pub fn strict_lineage(
    source_id: &SourceId,
    locator: &Iri,
    text_version: &ContentHash,
    text_object: &ContentHash,
    spans: &[ResolvedSpan],
    max_spans: usize,
) -> Result<Lineage> {
    if spans.is_empty() || spans.len() > max_spans {
        return Err(Error::limit());
    }
    let mut previous_end = None;
    let mut sources = Vec::with_capacity(spans.len());
    for resolved in spans {
        if resolved.span.start() >= resolved.span.end()
            || previous_end.is_some_and(|end| resolved.span.start() < end)
            || resolved.line_start == 0
            || resolved.line_start > resolved.line_end
        {
            return Err(Error::invalid("invalid strict lineage span"));
        }
        previous_end = Some(resolved.span.end());
        sources.push(obj([
            ("source_id", V::string(source_id.as_str())),
            ("kind", V::string("ctxql.source.extraction-text")),
            ("uri", V::string(locator.as_str())),
            ("version", V::string(text_version.as_str())),
            (
                "selectors",
                obj([
                    ("contract", V::string("ctxql-evidence/v1")),
                    (
                        "utf8",
                        obj([
                            ("start", V::integer(resolved.span.start() as u64)),
                            ("end", V::integer(resolved.span.end() as u64)),
                        ]),
                    ),
                    (
                        "line",
                        obj([
                            ("start", V::integer(resolved.line_start as u64)),
                            ("end", V::integer(resolved.line_end as u64)),
                        ]),
                    ),
                ]),
            ),
            ("content_hash", V::string(resolved.selected_hash.as_str())),
            ("object_hash", V::string(text_object.as_str())),
        ]));
    }
    Lineage::from_value(&obj([
        ("schema", V::string("ctxql.lineage.v1")),
        ("sources", V::Array(sources)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdb_core::evidence::Utf8Span;

    #[test]
    fn emits_verified_span_lineage_without_quotes() {
        let text = "alpha\n";
        let span = ResolvedSpan {
            span: Utf8Span::new(0, 5).unwrap(),
            selected_hash: ContentHash::of_bytes(b"alpha"),
            line_start: 1,
            line_end: 1,
        };
        let lineage = strict_lineage(
            &SourceId::new("source").unwrap(),
            &Iri::new("file:///x").unwrap(),
            &ContentHash::of_bytes(b"converter-bound-version"),
            &ContentHash::of_bytes(text.as_bytes()),
            &[span],
            1,
        )
        .unwrap();
        let bytes = lineage
            .projection()
            .canonical_bytes(cdb_core::Limits::default())
            .unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        assert!(!wire.contains("text_quote"));
        assert!(lineage.sources()[0].has_span());
        assert_eq!(
            lineage.sources()[0].verify(text.as_bytes()).unwrap(),
            cdb_core::evidence::VerificationOutcome::Verified
        );
    }
}
