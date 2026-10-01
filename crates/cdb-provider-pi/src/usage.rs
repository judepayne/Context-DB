use serde_json::Value;
use std::collections::BTreeSet;

/// Content-free provider accounting. No prompts, output, or tool payloads are retained.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_microusd: u64,
    pub requests: u64,
}

#[derive(Debug, Default)]
pub(crate) struct UsageAccumulator {
    seen: BTreeSet<String>,
    total: Usage,
}

impl UsageAccumulator {
    pub(crate) fn add(&mut self, key: &str, value: &Value) {
        if !self.seen.insert(key.to_owned()) {
            return;
        }
        self.total.input_tokens = self
            .total
            .input_tokens
            .saturating_add(find_u64(value, &["input_tokens", "input"]));
        self.total.output_tokens = self
            .total
            .output_tokens
            .saturating_add(find_u64(value, &["output_tokens", "output"]));
        self.total.cache_read_tokens = self
            .total
            .cache_read_tokens
            .saturating_add(find_u64(value, &["cache_read_tokens", "cacheRead"]));
        self.total.cache_write_tokens = self
            .total
            .cache_write_tokens
            .saturating_add(find_u64(value, &["cache_write_tokens", "cacheWrite"]));
        self.total.cost_microusd = self.total.cost_microusd.saturating_add(find_cost(value));
        self.total.requests = self.total.requests.saturating_add(1);
    }
    pub(crate) fn snapshot(&self) -> Usage {
        self.total.clone()
    }
}

fn find_u64(value: &Value, keys: &[&str]) -> u64 {
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(n) = map.get(*key).and_then(Value::as_u64) {
                    return n;
                }
            }
            map.values()
                .map(|v| find_u64(v, keys))
                .find(|n| *n != 0)
                .unwrap_or(0)
        }
        Value::Array(values) => values
            .iter()
            .map(|v| find_u64(v, keys))
            .find(|n| *n != 0)
            .unwrap_or(0),
        _ => 0,
    }
}

fn find_cost(value: &Value) -> u64 {
    if let Some(n) = value.get("cost_microusd").and_then(Value::as_u64) {
        return n;
    }
    if let Some(n) = value.get("cost").and_then(Value::as_f64) {
        if n.is_finite() && n >= 0.0 {
            return (n * 1_000_000.0).round() as u64;
        }
    }
    value
        .as_object()
        .and_then(|m| m.values().map(find_cost).find(|n| *n != 0))
        .unwrap_or(0)
}
