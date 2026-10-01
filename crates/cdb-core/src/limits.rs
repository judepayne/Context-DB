use crate::{Error, Result};
/// Operational limits, never canonical semantic configuration. Zero is a valid rejecting budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    input_bytes: usize,
    depth: usize,
    values: usize,
    work: usize,
    output_bytes: usize,
}
impl Limits {
    pub fn new(
        input_bytes: usize,
        depth: usize,
        values: usize,
        work: usize,
        output_bytes: usize,
    ) -> Result<Self> {
        if depth > 256 {
            return Err(Error::invalid("depth exceeds supported stack bound 256"));
        }
        Ok(Self {
            input_bytes,
            depth,
            values,
            work,
            output_bytes,
        })
    }
    pub fn input_bytes(self) -> usize {
        self.input_bytes
    }
    pub fn depth(self) -> usize {
        self.depth
    }
    pub fn values(self) -> usize {
        self.values
    }
    pub fn work(self) -> usize {
        self.work
    }
    pub fn output_bytes(self) -> usize {
        self.output_bytes
    }
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            input_bytes: 8 * 1024 * 1024,
            depth: 64,
            values: 100_000,
            work: 1_000_000,
            output_bytes: 16 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Budget {
    limits: Limits,
    values: usize,
    work: usize,
    bytes: usize,
}
impl Budget {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            values: 0,
            work: 0,
            bytes: 0,
        }
    }
    pub fn charge(&mut self, values: usize, work: usize, bytes: usize) -> Result<()> {
        let v = self.values.checked_add(values).ok_or_else(Error::limit)?;
        let w = self.work.checked_add(work).ok_or_else(Error::limit)?;
        let b = self.bytes.checked_add(bytes).ok_or_else(Error::limit)?;
        if v > self.limits.values {
            return Err(Error::new(
                crate::ErrorKind::Limit,
                "canonical value-count limit",
            ));
        }
        if w > self.limits.work {
            return Err(Error::new(crate::ErrorKind::Limit, "canonical work limit"));
        }
        if b > self.limits.input_bytes {
            return Err(Error::new(
                crate::ErrorKind::Limit,
                "canonical input-byte limit",
            ));
        }
        self.values = v;
        self.work = w;
        self.bytes = b;
        Ok(())
    }
}
