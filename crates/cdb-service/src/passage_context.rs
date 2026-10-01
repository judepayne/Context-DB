//! Exact, bounded document context. Context excerpts do not issue grounding handles.
use serde_json::{json, Value};

fn boundary(text: &str, maximum: usize) -> usize {
    let mut end = maximum.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

pub(crate) fn document_context(
    text: &str,
    start: usize,
    end: usize,
    previous: &[(usize, usize)],
) -> Value {
    let excerpt = |start: usize, end: usize| {
        json!({
            "text": &text[start..end],
            "selector": {"utf8": {"start": start, "end": end}}
        })
    };
    let opening_end = boundary(text, 4096);
    let mut offset = 0;
    let mut title = Value::Null;
    let mut headings: Vec<(usize, Value)> = Vec::new();
    for line in text.split_inclusive('\n') {
        let content = line.trim_end_matches(['\r', '\n']);
        if title.is_null() && !content.trim().is_empty() {
            // A pathological first line is not silently represented as a complete title.
            if content.len() <= 1024 {
                title = excerpt(offset, offset + content.len());
            } else {
                title = json!({"omitted": "title_byte_limit"});
            }
        }
        if offset > start {
            break;
        }
        let depth = content.bytes().take_while(|b| *b == b'#').count();
        if (1..=6).contains(&depth)
            && content.as_bytes().get(depth) == Some(&b' ')
            && content.len() <= 1024
        {
            headings.retain(|(level, _)| *level < depth);
            headings.push((depth, excerpt(offset, offset + content.len())));
        }
        offset += line.len();
    }
    json!({
        "schema": "ctxql-document-context/v1",
        "title": title,
        "active_headings": headings.into_iter().map(|(_, value)| value).collect::<Vec<_>>(),
        "opening": excerpt(0, opening_end),
        "opening_truncated": opening_end < text.len(),
        "context_is_not_an_issued_evidence_range": true,
        "coverage": {"current": {"start": start, "end": end},
            "previous": previous.iter().map(|(start,end)| json!({"start": start,"end":end})).collect::<Vec<_>>(),
            "document_bytes": text.len()}
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_unicode_opening_and_active_headings() {
        let text = format!(
            "# Loan\n## Parties\nBorrower\n## Terms\n{}",
            "é".repeat(3000)
        );
        let start = text.find("## Terms").unwrap();
        let value = document_context(&text, start, text.len(), &[(0, start)]);
        assert_eq!(value["title"]["text"], "# Loan");
        assert_eq!(value["active_headings"][1]["text"], "## Terms");
        assert_eq!(value["coverage"]["previous"][0]["end"], start);
        let end = value["opening"]["selector"]["utf8"]["end"]
            .as_u64()
            .unwrap() as usize;
        assert!(end <= 4096 && text.is_char_boundary(end));
        assert_eq!(value["opening"]["text"], &text[..end]);
        assert_eq!(value["opening_truncated"], true);
    }
}
