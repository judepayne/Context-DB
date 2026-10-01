//! Content-free P6 evaluation aggregates adapted from hmem's evaluation layout.

use cdb_core::{CanonicalValue as V, Error, Result};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QualityCounts {
    pub true_positive: u64,
    pub false_positive: u64,
    pub false_negative: u64,
    pub exact_coordinates: u64,
    pub coordinate_failures: u64,
    pub connected_bundles: u64,
    pub disconnected_bundles: u64,
    pub entity_duplicates: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Evaluation {
    quality: QualityCounts,
    latency_micros: BTreeMap<String, Vec<u64>>,
    tokens: u64,
    cost_microusd: u64,
}
impl Evaluation {
    pub fn quality_mut(&mut self) -> &mut QualityCounts {
        &mut self.quality
    }
    pub fn observe_latency(&mut self, stage: &str, micros: u64) -> Result<()> {
        const STAGES: &[&str] = &[
            "conversion",
            "planning",
            "provider",
            "tool",
            "validation",
            "admission",
            "projection",
            "preparation",
            "reasoning",
            "traversal",
            "recording",
            "replay",
        ];
        if !STAGES.contains(&stage) {
            return Err(Error::invalid("evaluation stage"));
        }
        let samples = self.latency_micros.entry(stage.to_owned()).or_default();
        if samples.len() >= 100_000 {
            return Err(Error::limit());
        }
        samples.push(micros);
        Ok(())
    }
    pub fn add_usage(&mut self, tokens: u64, cost_microusd: u64) -> Result<()> {
        self.tokens = self.tokens.checked_add(tokens).ok_or_else(Error::limit)?;
        self.cost_microusd = self
            .cost_microusd
            .checked_add(cost_microusd)
            .ok_or_else(Error::limit)?;
        Ok(())
    }
    pub fn report(&self) -> V {
        let ratio = |numerator: u64, denominator: u64| {
            V::object([
                ("numerator".into(), V::integer(numerator)),
                ("denominator".into(), V::integer(denominator)),
            ])
            .expect("static fields")
        };
        let latencies = self
            .latency_micros
            .iter()
            .map(|(stage, samples)| {
                let mut sorted = samples.clone();
                sorted.sort_unstable();
                let percentile = |n: usize| {
                    sorted
                        .get(sorted.len().saturating_sub(1).saturating_mul(n) / 100)
                        .copied()
                        .unwrap_or(0)
                };
                (
                    stage.clone(),
                    V::object([
                        ("samples".into(), V::integer(sorted.len() as u64)),
                        ("p50_micros".into(), V::integer(percentile(50))),
                        ("p95_micros".into(), V::integer(percentile(95))),
                        (
                            "max_micros".into(),
                            V::integer(sorted.last().copied().unwrap_or(0)),
                        ),
                    ])
                    .expect("static fields"),
                )
            })
            .collect();
        V::object([
            ("schema".into(), V::string("ctxql-p6-evaluation/v1")),
            (
                "precision".into(),
                ratio(
                    self.quality.true_positive,
                    self.quality
                        .true_positive
                        .saturating_add(self.quality.false_positive),
                ),
            ),
            (
                "recall".into(),
                ratio(
                    self.quality.true_positive,
                    self.quality
                        .true_positive
                        .saturating_add(self.quality.false_negative),
                ),
            ),
            (
                "coordinates".into(),
                ratio(
                    self.quality.exact_coordinates,
                    self.quality
                        .exact_coordinates
                        .saturating_add(self.quality.coordinate_failures),
                ),
            ),
            (
                "connectivity".into(),
                ratio(
                    self.quality.connected_bundles,
                    self.quality
                        .connected_bundles
                        .saturating_add(self.quality.disconnected_bundles),
                ),
            ),
            (
                "entity_duplicates".into(),
                V::integer(self.quality.entity_duplicates),
            ),
            ("latency".into(), V::Object(latencies)),
            ("tokens".into(), V::integer(self.tokens)),
            ("cost_microusd".into(), V::integer(self.cost_microusd)),
            ("threshold".into(), V::Null),
        ])
        .expect("static fields")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_is_aggregate_only_and_has_no_quality_threshold() {
        let mut evaluation = Evaluation::default();
        evaluation.quality_mut().true_positive = 3;
        evaluation.observe_latency("provider", 10).unwrap();
        evaluation.observe_latency("provider", 30).unwrap();
        evaluation.add_usage(12, 34).unwrap();
        let report = evaluation.report();
        assert_eq!(report.field("threshold").unwrap(), &V::Null);
        assert!(report.field("source_text").is_err());
    }
}
