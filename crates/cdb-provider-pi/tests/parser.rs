use cdb_provider_pi::parser::*;

fn windows(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|s| (*s).to_owned()).collect()
}
fn claim(window: &str, bundle: &str, id: &str, subject: &str, refs: &str) -> String {
    format!(
        r#"{{"window_id":"{window}","bundle_id":"{bundle}","claim_id":"{id}","subject":{{"entity_id":"{subject}","spelling":"Acme","type_iri":"https://example.test/Organization"}},"predicate_iri":"https://example.test/hasName","object":{{"lexical":"Acme","datatype_iri":"http://www.w3.org/2001/XMLSchema#string"}},"relation_type_iri":"https://example.test/relation","claim_type_iri":"https://example.test/assertion","confidence":"0.9","endpoint_type_claim_ids":{refs}}}"#
    )
}
fn metadata(window: &str, bundle: &str, id: &str) -> String {
    format!(
        r#"{{"window_id":"{window}","bundle_id":"{bundle}","claim_id":"{id}","locator":"file:///doc.txt","text_version":"sha256:abc","coordinates":[{{"line_id":"line-1","start":0,"end":4}}]}}"#
    )
}
fn block(c: &str, m: &str) -> String {
    format!("CLAIM:\n{c}\nCLAIM_METADATA:\n{m}\n---")
}

#[test]
fn accepts_exact_block_and_single_sentinel() {
    let text = block(
        &claim("w1", "b1", "c1", "e1", "[]"),
        &metadata("w1", "b1", "c1"),
    );
    assert!(
        matches!(parse_output(&text, &windows(&["w1"]), &ParseLimits::default()), Ok(ParsedOutput::Claims(v)) if v.len()==1)
    );
    assert_eq!(
        parse_output("NO_CLAIMS", &windows(&["w1"]), &ParseLimits::default()),
        Ok(ParsedOutput::NoClaims {
            window_id: "w1".into()
        })
    );
}

#[test]
fn rejects_prose_fences_forbidden_sections_and_truncation() {
    let valid = block(
        &claim("w1", "b1", "c1", "e1", "[]"),
        &metadata("w1", "b1", "c1"),
    );
    for bad in [
        format!("prose\n{valid}"),
        format!("```\n{valid}\n```"),
        "MEMORY:\nx".into(),
        "EVIDENCE:\nx".into(),
        valid.trim_end_matches("---").into(),
    ] {
        assert!(
            parse_output(&bad, &windows(&["w1"]), &ParseLimits::default()).is_err(),
            "accepted {bad}"
        );
    }
}

#[test]
fn rejects_unknown_fields_and_duplicate_json_fields() {
    let c = claim("w1", "b1", "c1", "e1", "[]").replacen('{', "{\"surprise\":true,", 1);
    assert!(parse_output(
        &block(&c, &metadata("w1", "b1", "c1")),
        &windows(&["w1"]),
        &ParseLimits::default()
    )
    .is_err());
    let c = claim("w1", "b1", "c1", "e1", "[]").replacen(
        "\"window_id\":\"w1\"",
        "\"window_id\":\"w1\",\"window_id\":\"w1\"",
        1,
    );
    assert!(parse_output(
        &block(&c, &metadata("w1", "b1", "c1")),
        &windows(&["w1"]),
        &ParseLimits::default()
    )
    .is_err());
}

#[test]
fn rejects_duplicate_ids_unresolved_refs_and_mismatch() {
    let one = block(
        &claim("w1", "b1", "c1", "e1", "[]"),
        &metadata("w1", "b1", "c1"),
    );
    assert_eq!(
        parse_output(
            &(one.clone() + "\n" + &one),
            &windows(&["w1"]),
            &ParseLimits::default()
        ),
        Err(ParseError::DuplicateClaimId)
    );
    let unresolved = block(
        &claim("w1", "b1", "c1", "e1", "[\"missing\"]"),
        &metadata("w1", "b1", "c1"),
    );
    assert_eq!(
        parse_output(&unresolved, &windows(&["w1"]), &ParseLimits::default()),
        Err(ParseError::UnresolvedReference)
    );
    let mismatch = block(
        &claim("w1", "b1", "c1", "e1", "[]"),
        &metadata("w1", "b1", "other"),
    );
    assert_eq!(
        parse_output(&mismatch, &windows(&["w1"]), &ParseLimits::default()),
        Err(ParseError::Mismatch)
    );
}

#[test]
fn rejects_batch_ambiguity_and_unknown_windows() {
    assert_eq!(
        parse_output(
            "NO_CLAIMS",
            &windows(&["w1", "w2"]),
            &ParseLimits::default()
        ),
        Err(ParseError::CrossWindowAmbiguity)
    );
    let a = block(
        &claim("w1", "same", "c1", "entity", "[]"),
        &metadata("w1", "same", "c1"),
    );
    let b = block(
        &claim("w2", "same", "c2", "other", "[]"),
        &metadata("w2", "same", "c2"),
    );
    assert_eq!(
        parse_output(
            &(a + "\n" + &b),
            &windows(&["w1", "w2"]),
            &ParseLimits::default()
        ),
        Err(ParseError::CrossWindowAmbiguity)
    );
    let bad = block(&claim("w3", "b", "c", "e", "[]"), &metadata("w3", "b", "c"));
    assert_eq!(
        parse_output(&bad, &windows(&["w1", "w2"]), &ParseLimits::default()),
        Err(ParseError::UnknownWindow)
    );
}

#[test]
fn no_fuzzy_repair_of_sentinel_headers_or_coordinates() {
    for bad in [" NO_CLAIMS", "NO_CLAIMS\n", "no_claims"] {
        assert!(parse_output(bad, &windows(&["w1"]), &ParseLimits::default()).is_err());
    }
    let bad_meta =
        metadata("w1", "b1", "c1").replace("\"start\":0,\"end\":4", "\"start\":4,\"end\":4");
    assert!(parse_output(
        &block(&claim("w1", "b1", "c1", "e1", "[]"), &bad_meta),
        &windows(&["w1"]),
        &ParseLimits::default()
    )
    .is_err());
}
