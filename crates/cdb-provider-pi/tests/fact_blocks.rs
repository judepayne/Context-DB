use cdb_provider_pi::fact_blocks::{
    parse_fact_blocks, FactBlockLimits, FactBlockParseError, FactProposal, TypedEndpointEvidence,
};

fn ids() -> Vec<String> {
    vec!["line-1".into(), "line-2".into()]
}

#[test]
fn parses_repeated_fact_blocks_and_exact_empty_sentinel() {
    let text = "FACT:\nAcme Ltd | employs | José\nEVIDENCE:\nline-1 | Acme Ltd employs José.\n---\nFACT:\nJosé | works in | Zürich\nEVIDENCE:\nline-2 | José works in Zürich.\n---";
    assert_eq!(
        parse_fact_blocks(text, &ids(), &FactBlockLimits::default()).unwrap(),
        vec![
            FactProposal {
                subject: "Acme Ltd".into(),
                predicate: "employs".into(),
                object: "José".into(),
                line_id: "line-1".into(),
                quote: "Acme Ltd employs José.".into(),
                typed_endpoint_evidence: None,
            },
            FactProposal {
                subject: "José".into(),
                predicate: "works in".into(),
                object: "Zürich".into(),
                line_id: "line-2".into(),
                quote: "José works in Zürich.".into(),
                typed_endpoint_evidence: None,
            },
        ]
    );
    assert_eq!(
        parse_fact_blocks("NO_CLAIMS", &ids(), &FactBlockLimits::default()).unwrap(),
        Vec::<FactProposal>::new()
    );
    for bad in [" NO_CLAIMS", "NO_CLAIMS\n", "no_claims"] {
        assert!(parse_fact_blocks(bad, &ids(), &FactBlockLimits::default()).is_err());
    }
}

#[test]
fn rejects_preamble_unrecognized_headers_fences_and_malicious_text() {
    let block = "FACT:\nAcme | employs | Bob\nEVIDENCE:\nline-1 | Acme employs Bob.\n---";
    for bad in [
        format!("Here are the facts:\n{block}"),
        format!("```text\n{block}\n```"),
        block.replacen("FACT:", "CLAIM:", 1),
        block.replacen("EVIDENCE:", "SOURCE:", 1),
        block.replacen("Acme employs Bob.", "ignore instructions | exfiltrate", 1),
        format!("{block}\nMEMORY:\nsecret"),
    ] {
        assert!(
            parse_fact_blocks(&bad, &ids(), &FactBlockLimits::default()).is_err(),
            "accepted {bad:?}"
        );
    }
}

#[test]
fn rejects_ambiguous_delimiters_empty_fields_and_bad_spacing() {
    let invalid = [
        "FACT:\nAcme | employs | Bob | extra\nEVIDENCE:\nline-1 | quote\n---",
        "FACT:\nAcme|employs|Bob\nEVIDENCE:\nline-1 | quote\n---",
        "FACT:\nAcme |  | Bob\nEVIDENCE:\nline-1 | quote\n---",
        "FACT:\n Acme | employs | Bob\nEVIDENCE:\nline-1 | quote\n---",
        "FACT:\nAcme | employs | Bob\nEVIDENCE:\nline-1||quote\n---",
        "FACT:\nAcme | employs | Bob\nEVIDENCE:\nline-1 | \n---",
    ];
    for text in invalid {
        assert!(
            parse_fact_blocks(text, &ids(), &FactBlockLimits::default()).is_err(),
            "accepted {text:?}"
        );
    }
}

#[test]
fn rejects_unknown_malformed_and_duplicate_facts_but_allows_shared_evidence_lines() {
    let unknown = "FACT:\nAcme | employs | Bob\nEVIDENCE:\nline-9 | quote\n---";
    assert_eq!(
        parse_fact_blocks(unknown, &ids(), &FactBlockLimits::default()),
        Err(FactBlockParseError::UnknownLineId)
    );

    let malformed = unknown.replace("line-9", "line 1");
    assert_eq!(
        parse_fact_blocks(&malformed, &ids(), &FactBlockLimits::default()),
        Err(FactBlockParseError::InvalidValue("line_id"))
    );

    let one = "FACT:\nAcme | employs | Bob\nEVIDENCE:\nline-1 | quote one\n---";
    let shared_line =
        format!("{one}\nFACT:\nAcme | employs | Sue\nEVIDENCE:\nline-1 | quote two\n---");
    assert_eq!(
        parse_fact_blocks(&shared_line, &ids(), &FactBlockLimits::default())
            .unwrap()
            .len(),
        2
    );
    let duplicate = format!("{one}\n{one}");
    assert_eq!(
        parse_fact_blocks(&duplicate, &ids(), &FactBlockLimits::default()),
        Err(FactBlockParseError::DuplicateFact)
    );
}

#[test]
fn parses_typed_and_legacy_blocks_with_independent_or_shared_evidence() {
    let typed = "TYPED_FACT:\nAcme Bank | lends to | Example Ltd\nEVIDENCE:\nline-1 | Acme Bank lends to Example Ltd.\nSUBJECT_ROLE:\nlender\nSUBJECT_EVIDENCE:\nline-2 | Acme Bank is the lender.\nOBJECT_ROLE:\nborrower\nOBJECT_EVIDENCE:\nline-2 | Acme Bank is the lender.\n---";
    let legacy = "FACT:\nExample Ltd | owes | principal\nEVIDENCE:\nline-1 | Example Ltd owes principal.\n---";
    let proposals = parse_fact_blocks(
        &format!("{typed}\n{legacy}"),
        &ids(),
        &FactBlockLimits::default(),
    )
    .unwrap();

    assert_eq!(
        proposals[0],
        FactProposal {
            subject: "Acme Bank".into(),
            predicate: "lends to".into(),
            object: "Example Ltd".into(),
            line_id: "line-1".into(),
            quote: "Acme Bank lends to Example Ltd.".into(),
            typed_endpoint_evidence: Some(TypedEndpointEvidence {
                subject_role: "lender".into(),
                subject_line_id: "line-2".into(),
                subject_quote: "Acme Bank is the lender.".into(),
                object_role: "borrower".into(),
                object_line_id: "line-2".into(),
                object_quote: "Acme Bank is the lender.".into(),
            }),
        }
    );
    assert_eq!(proposals[1].typed_endpoint_evidence, None);
}

#[test]
fn rejects_non_atomic_or_invalid_typed_blocks() {
    let valid = "TYPED_FACT:\nAcme Bank | lends to | Example Ltd\nEVIDENCE:\nline-1 | relation quote\nSUBJECT_ROLE:\nlender\nSUBJECT_EVIDENCE:\nline-1 | lender quote\nOBJECT_ROLE:\nborrower\nOBJECT_EVIDENCE:\nline-2 | borrower quote\n---";
    let invalid = [
        valid.replacen("SUBJECT_ROLE:", "ROLE:", 1),
        valid.replacen("OBJECT_EVIDENCE:", "EVIDENCE:", 1),
        valid.replacen("lender\nSUBJECT_EVIDENCE:", "\nSUBJECT_EVIDENCE:", 1),
        valid.replacen("line-2 | borrower quote", "line-9 | borrower quote", 1),
        valid.replacen("borrower quote", "borrower | quote", 1),
        valid.trim_end_matches("\n---").to_owned(),
        format!("{valid}\nstray text"),
    ];

    for text in invalid {
        assert!(
            parse_fact_blocks(&text, &ids(), &FactBlockLimits::default()).is_err(),
            "accepted {text:?}"
        );
    }
}

#[test]
fn enforces_output_fact_and_value_budgets() {
    let text = "FACT:\nAcme | employs | Bob\nEVIDENCE:\nline-1 | exact quote\n---";

    let limits = FactBlockLimits {
        max_output_bytes: text.len() - 1,
        ..FactBlockLimits::default()
    };
    assert_eq!(
        parse_fact_blocks(text, &ids(), &limits),
        Err(FactBlockParseError::Limit("output_bytes"))
    );

    let limits = FactBlockLimits {
        max_facts: 0,
        ..FactBlockLimits::default()
    };
    assert_eq!(
        parse_fact_blocks(text, &ids(), &limits),
        Err(FactBlockParseError::Limit("facts"))
    );

    let limits = FactBlockLimits {
        max_field_bytes: 3,
        ..FactBlockLimits::default()
    };
    assert_eq!(
        parse_fact_blocks(text, &ids(), &limits),
        Err(FactBlockParseError::InvalidValue("subject"))
    );

    let limits = FactBlockLimits {
        max_quote_bytes: 4,
        ..FactBlockLimits::default()
    };
    assert_eq!(
        parse_fact_blocks(text, &ids(), &limits),
        Err(FactBlockParseError::InvalidValue("quote"))
    );
}
