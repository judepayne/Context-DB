//! Constant-space emitter for the existing canonical function-root hashes array.
use crate::artifact::FunctionManifest;
use crate::canonical::Domain;
use crate::id::ContentHash;
use crate::{CanonicalValue as V, Error, Limits, Result};
use sha2::{Digest, Sha256};

pub struct FunctionRootStream {
    digest: Sha256,
    suffix: Vec<u8>,
    count: u64,
    max_calls: u64,
}
impl FunctionRootStream {
    /// `limits` bounds framing/identity strings; `max_calls` separately bounds
    /// lifetime work. No call hashes or payloads are retained.
    pub fn new(
        output: bool,
        manifest: &FunctionManifest,
        limits: Limits,
        max_calls: u64,
    ) -> Result<Self> {
        let string = |s: &str| V::string(s).canonical_bytes(limits);
        let domain = if output {
            Domain::FunctionOutputRoot
        } else {
            Domain::FunctionInputRoot
        };
        let mut prefix = b"{\"domain\":".to_vec();
        prefix.extend(string(domain.as_str())?);
        prefix.extend(b",\"payload\":{\"hashes\":[");
        let mut suffix = b"],\"manifest_hash\":".to_vec();
        suffix.extend(string(manifest.hash().as_str())?);
        suffix.extend(b",\"name\":");
        suffix.extend(string(manifest.name().as_str())?);
        suffix.extend(b",\"version\":");
        suffix.extend(string(manifest.version().as_str())?);
        suffix.extend(b"},\"version\":\"ctxql-canonical/v1\"}");
        let size = prefix
            .len()
            .checked_add(suffix.len())
            .ok_or_else(Error::limit)?;
        if size > limits.output_bytes()
            || size > limits.input_bytes()
            || size > limits.work()
            || limits.values() < 9
            || limits.depth() < 4
        {
            return Err(Error::limit());
        }
        let mut digest = Sha256::new();
        digest.update(prefix);
        Ok(Self {
            digest,
            suffix,
            count: 0,
            max_calls,
        })
    }
    pub fn push(&mut self, hash: &ContentHash) -> Result<()> {
        let next = self.count.checked_add(1).ok_or_else(Error::limit)?;
        if next > self.max_calls {
            return Err(Error::limit());
        }
        if self.count != 0 {
            self.digest.update(b",");
        }
        // ContentHash is validated fixed ASCII, hence requires no escaping.
        self.digest.update(b"\"");
        self.digest.update(hash.as_str().as_bytes());
        self.digest.update(b"\"");
        self.count = next;
        Ok(())
    }
    pub fn count(&self) -> u64 {
        self.count
    }
    pub fn finish(mut self) -> Result<ContentHash> {
        self.digest.update(&self.suffix);
        ContentHash::parse(format!("sha256:{:x}", self.digest.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counter_overflow_is_transactional() {
        let mut stream = FunctionRootStream {
            digest: Sha256::new(),
            suffix: vec![],
            count: u64::MAX,
            max_calls: u64::MAX,
        };
        let before = stream.digest.clone().finalize();
        assert!(stream.push(&ContentHash::of_bytes(b"x")).is_err());
        assert_eq!(stream.count(), u64::MAX);
        assert_eq!(before, stream.digest.finalize());
    }
}
