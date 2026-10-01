mod common;
use cdb_core::{evidence::*, id::ContentHash};
use common::*;
#[test]
fn independent_utf8_fixture() {
    let f = json(include_str!(
        "../../../fixtures/conformance/evidence/utf8-v1.json"
    ));
    let text = f.field("text").unwrap().as_str().unwrap();
    assert_eq!(
        ContentHash::of_bytes(text.as_bytes()).as_str(),
        f.field("version").unwrap().as_str().unwrap()
    );
    let span = Utf8Span::new(8, 11).unwrap();
    assert_eq!(span.select(text).unwrap(), "漢");
    assert_eq!(
        ContentHash::of_bytes(span.select(text).unwrap().as_bytes()).as_str(),
        "sha256:fc9f0d61dd80076ae5f0e41688aa0c3e8727b232b7a8c40c4f0671e0cd5d94c9"
    );
    assert!(Utf8Span::new(2, 3).unwrap().select(text).is_err());
    assert_eq!(
        Utf8Span::from_scalars(text, 2, 3).unwrap(),
        Utf8Span::new(3, 7).unwrap()
    );
    assert_eq!(
        Utf8Span::from_chunk(
            text,
            Utf8Span::new(3, 11).unwrap(),
            Utf8Span::new(5, 8).unwrap()
        )
        .unwrap(),
        span
    );
    assert_eq!(Utf8Span::new(0, 0).unwrap().select(text).unwrap(), "");
}
#[test]
fn selectors_not_full_document_and_hashes_distinct() {
    let text = "Aé🙂\n漢Z";
    let v = json(&format!(
        r#"{{"source_id":"s","kind":"document","version":"{}","content_hash":"{}","selectors":{{"contract":"ctxql-evidence/v1","utf8":{{"start":8,"end":11}},"line":{{"start":2,"end":2}},"text_quote":{{"exact":"漢"}}}}}}"#,
        ContentHash::of_bytes(text.as_bytes()).as_str(),
        ContentHash::of_bytes("漢".as_bytes()).as_str()
    ));
    let s = SourceReference::from_value(&v).unwrap();
    assert_eq!(
        s.verify(text.as_bytes()).unwrap(),
        VerificationOutcome::Verified
    );
    assert_eq!(s.verify(b"changed").unwrap(), VerificationOutcome::Changed);
    assert!(s.has_span());
    assert_eq!(SourceReference::from_value(&s.projection()).unwrap(), s);
    for selectors in [
        r#"{"contract":"ctxql-evidence/v1","utf8":{"start":0,"end":1},"whole_document":true}"#,
        r#"{"contract":"ctxql-evidence/v1","char":{"start":0,"end":1}}"#,
        r#"{"contract":"ctxql-evidence/v1","utf8":{"start":1,"end":0}}"#,
    ] {
        assert!(validate_selectors(&json(selectors)).is_err());
    }
}
