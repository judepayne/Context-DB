//! Pure, version-pinned label scoring. This module grants no visibility and
//! performs no graph I/O. Preparation must authorize candidates and labels before
//! applying these scores or semantic caps, and record the resolved landings.
use cdb_core::{id::ResourceId, limits::Budget, Error, ErrorKind, Limits, Result};
use std::collections::BTreeSet;

pub const RESOLVER: &str = "ctxql.lexical-token-overlap/v1";
pub const UNICODE_VERSION: (u8, u8, u8) = char::UNICODE_VERSION;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    minimum_overlap: u64,
}
impl Config {
    /// The semantic configuration must explicitly pin both resolver and Unicode
    /// tables. An incompatible declaration is not an exact-only fallback.
    pub fn new(resolver: &str, unicode: (u8, u8, u8), minimum_overlap: u64) -> Result<Self> {
        if resolver != RESOLVER || unicode != UNICODE_VERSION {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "lexical resolver identity",
            ));
        }
        if minimum_overlap == 0 {
            return Err(Error::invalid("lexical minimum overlap must be positive"));
        }
        Ok(Self { minimum_overlap })
    }
    pub fn minimum_overlap(self) -> u64 {
        self.minimum_overlap
    }
}

fn lowercase(text: &str, budget: &mut Budget) -> Result<String> {
    budget.charge(1, text.len(), text.len())?;
    let mut out = String::new();
    for ch in text.chars().flat_map(char::to_lowercase) {
        budget.charge(0, 1, ch.len_utf8())?;
        out.push(ch);
    }
    Ok(out)
}
fn tokens<'a>(text: &'a str, budget: &mut Budget) -> Result<BTreeSet<&'a str>> {
    let mut out = BTreeSet::new();
    for token in text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
    {
        // Conservative comparison work allowance; token text is borrowed rather
        // than copied. The ordered set is independent of hash-map random seeds.
        budget.charge(
            1,
            token
                .len()
                .checked_mul(usize::BITS as usize)
                .ok_or_else(Error::limit)?,
            0,
        )?;
        out.insert(token);
    }
    Ok(out)
}

/// Best score over all labels. Partial overlap never inspects IRI components.
/// Full-label equality lowercases but does not trim, stem or normalize Unicode.
/// All supplied labels are budgeted even after an exact match; this is not a
/// permission-pruning or early-top-K API. Ranking/deduplication belongs to the
/// authorized landing controller (score descending, ID ascending).
pub fn score(
    anchor: &str,
    id: &ResourceId,
    labels: &[String],
    config: Config,
    limits: Limits,
) -> Result<Option<u64>> {
    let mut budget = Budget::new(limits);
    budget.charge(1, id.as_str().len(), id.as_str().len())?;
    let query = lowercase(anchor, &mut budget)?;
    let q = tokens(&query, &mut budget)?;
    let exact_score = u64::try_from(q.len())
        .map_err(|_| Error::limit())?
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(Error::limit)?;
    let mut best = (anchor == id.as_str()).then_some(exact_score);
    for label in labels {
        let lower = lowercase(label, &mut budget)?;
        let l = tokens(&lower, &mut budget)?;
        let overlap = u64::try_from(q.intersection(&l).count()).map_err(|_| Error::limit())?;
        let current = if query == lower {
            Some(exact_score)
        } else if !q.is_empty() && overlap >= config.minimum_overlap {
            Some(overlap)
        } else {
            None
        };
        best = best.max(current);
    }
    Ok(best)
}
