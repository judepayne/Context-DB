use std::collections::BTreeSet;

/// Resource bounds for the compact fact-first provider grammar.
#[derive(Clone, Debug)]
pub struct FactBlockLimits {
    pub max_output_bytes: usize,
    pub max_facts: usize,
    pub max_field_bytes: usize,
    pub max_line_id_bytes: usize,
    pub max_quote_bytes: usize,
}

impl Default for FactBlockLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: 256 * 1024,
            max_facts: 128,
            max_field_bytes: 4096,
            max_line_id_bytes: 4096,
            max_quote_bytes: 4096,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedEndpointEvidence {
    pub subject_role: String,
    pub subject_line_id: String,
    pub subject_quote: String,
    pub object_role: String,
    pub object_line_id: String,
    pub object_quote: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactProposal {
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub line_id: String,
    pub quote: String,
    pub typed_endpoint_evidence: Option<TypedEndpointEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FactBlockParseError {
    Limit(&'static str),
    Grammar(&'static str),
    InvalidValue(&'static str),
    UnknownLineId,
    DuplicateFact,
}

impl std::fmt::Display for FactBlockParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for FactBlockParseError {}

/// Parse a complete compact fact response without repairing provider output.
///
/// Evidence IDs must be members of `host_line_ids`. Quotes are retained
/// verbatim; resolving them against source text belongs to the host.
pub fn parse_fact_blocks<S: AsRef<str>>(
    text: &str,
    host_line_ids: &[S],
    limits: &FactBlockLimits,
) -> Result<Vec<FactProposal>, FactBlockParseError> {
    if text.len() > limits.max_output_bytes {
        return Err(FactBlockParseError::Limit("output_bytes"));
    }
    if text == "NO_CLAIMS" {
        return Ok(Vec::new());
    }
    if text.trim() == "NO_CLAIMS" {
        return Err(FactBlockParseError::Grammar("sentinel_must_be_exact"));
    }
    if text.is_empty() {
        return Err(FactBlockParseError::Grammar("empty"));
    }
    if text.contains('\r') || text.contains("```") {
        return Err(FactBlockParseError::Grammar("fences_or_cr"));
    }

    let allowed_ids: BTreeSet<&str> = host_line_ids.iter().map(AsRef::as_ref).collect();
    let lines: Vec<&str> = text.lines().collect();
    let mut proposals = Vec::new();
    let mut seen_facts = BTreeSet::new();
    let mut i = 0;

    while i < lines.len() {
        if proposals.len() >= limits.max_facts {
            return Err(FactBlockParseError::Limit("facts"));
        }
        let typed = match lines[i] {
            "FACT:" => false,
            "TYPED_FACT:" => true,
            _ => return Err(FactBlockParseError::Grammar("expected_fact_header")),
        };
        let block_len = if typed { 13 } else { 5 };
        let fact_line = *lines
            .get(i + 1)
            .ok_or(FactBlockParseError::Grammar("truncated_fact"))?;
        if lines.get(i + 2) != Some(&"EVIDENCE:") {
            return Err(FactBlockParseError::Grammar("expected_evidence_header"));
        }
        let evidence_line = *lines
            .get(i + 3)
            .ok_or(FactBlockParseError::Grammar("truncated_evidence"))?;
        if lines.get(i + block_len - 1) != Some(&"---") {
            return Err(FactBlockParseError::Grammar("missing_terminator"));
        }

        let [subject, predicate, object] = split_fields::<3>(fact_line, "fact_fields")?;
        validate_text(subject, limits.max_field_bytes, "subject")?;
        validate_text(predicate, limits.max_field_bytes, "predicate")?;
        validate_text(object, limits.max_field_bytes, "object")?;

        let [line_id, quote] = parse_evidence(evidence_line, &allowed_ids, limits)?;
        let typed_endpoint_evidence = if typed {
            if lines.get(i + 4) != Some(&"SUBJECT_ROLE:") {
                return Err(FactBlockParseError::Grammar("expected_subject_role_header"));
            }
            let subject_role = *lines
                .get(i + 5)
                .ok_or(FactBlockParseError::Grammar("truncated_subject_role"))?;
            validate_text(subject_role, limits.max_field_bytes, "subject_role")?;
            if lines.get(i + 6) != Some(&"SUBJECT_EVIDENCE:") {
                return Err(FactBlockParseError::Grammar(
                    "expected_subject_evidence_header",
                ));
            }
            let subject_evidence = *lines
                .get(i + 7)
                .ok_or(FactBlockParseError::Grammar("truncated_subject_evidence"))?;
            let [subject_line_id, subject_quote] =
                parse_evidence(subject_evidence, &allowed_ids, limits)?;

            if lines.get(i + 8) != Some(&"OBJECT_ROLE:") {
                return Err(FactBlockParseError::Grammar("expected_object_role_header"));
            }
            let object_role = *lines
                .get(i + 9)
                .ok_or(FactBlockParseError::Grammar("truncated_object_role"))?;
            validate_text(object_role, limits.max_field_bytes, "object_role")?;
            if lines.get(i + 10) != Some(&"OBJECT_EVIDENCE:") {
                return Err(FactBlockParseError::Grammar(
                    "expected_object_evidence_header",
                ));
            }
            let object_evidence = *lines
                .get(i + 11)
                .ok_or(FactBlockParseError::Grammar("truncated_object_evidence"))?;
            let [object_line_id, object_quote] =
                parse_evidence(object_evidence, &allowed_ids, limits)?;

            Some(TypedEndpointEvidence {
                subject_role: subject_role.to_owned(),
                subject_line_id: subject_line_id.to_owned(),
                subject_quote: subject_quote.to_owned(),
                object_role: object_role.to_owned(),
                object_line_id: object_line_id.to_owned(),
                object_quote: object_quote.to_owned(),
            })
        } else {
            None
        };

        if !seen_facts.insert((subject, predicate, object, line_id, quote)) {
            return Err(FactBlockParseError::DuplicateFact);
        }
        proposals.push(FactProposal {
            subject: subject.to_owned(),
            predicate: predicate.to_owned(),
            object: object.to_owned(),
            line_id: line_id.to_owned(),
            quote: quote.to_owned(),
            typed_endpoint_evidence,
        });
        i += block_len;
    }

    Ok(proposals)
}

fn split_fields<'a, const N: usize>(
    line: &'a str,
    error: &'static str,
) -> Result<[&'a str; N], FactBlockParseError> {
    let fields: Vec<_> = line.split(" | ").collect();
    let fields: [&str; N] = fields
        .try_into()
        .map_err(|_| FactBlockParseError::Grammar(error))?;
    if fields.iter().any(|field| field.contains('|')) {
        return Err(FactBlockParseError::Grammar(error));
    }
    Ok(fields)
}

fn validate_text(
    value: &str,
    max_bytes: usize,
    name: &'static str,
) -> Result<(), FactBlockParseError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(FactBlockParseError::InvalidValue(name));
    }
    Ok(())
}

fn parse_evidence<'a>(
    line: &'a str,
    allowed_ids: &BTreeSet<&str>,
    limits: &FactBlockLimits,
) -> Result<[&'a str; 2], FactBlockParseError> {
    let [line_id, quote] = split_fields::<2>(line, "evidence_fields")?;
    validate_line_id(line_id, limits.max_line_id_bytes)?;
    validate_text(quote, limits.max_quote_bytes, "quote")?;
    if !allowed_ids.contains(line_id) {
        return Err(FactBlockParseError::UnknownLineId);
    }
    Ok([line_id, quote])
}

fn validate_line_id(value: &str, max_bytes: usize) -> Result<(), FactBlockParseError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(FactBlockParseError::InvalidValue("line_id"));
    }
    Ok(())
}
