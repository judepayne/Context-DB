use crate::id::ContentHash;
use crate::value::obj;
use crate::{CanonicalValue as V, Error, Limits, Result};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Domain {
    Plan,
    Response,
    FunctionInput,
    FunctionOutput,
    FunctionInputRoot,
    FunctionOutputRoot,
    StructuredProduct,
    TextProduct,
    StructuredClaim,
}
impl Domain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "ctxql.plan",
            Self::Response => "ctxql.response",
            Self::FunctionInput => "ctxql.function.input",
            Self::FunctionOutput => "ctxql.function.output",
            Self::FunctionInputRoot => "ctxql.function.input-root",
            Self::FunctionOutputRoot => "ctxql.function.output-root",
            Self::StructuredProduct => "ctxql.product.structured",
            Self::TextProduct => "ctxql.product.text",
            Self::StructuredClaim => "ctxql.structured-claim",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        for d in [
            Self::Plan,
            Self::Response,
            Self::FunctionInput,
            Self::FunctionOutput,
            Self::FunctionInputRoot,
            Self::FunctionOutputRoot,
            Self::StructuredProduct,
            Self::TextProduct,
            Self::StructuredClaim,
        ] {
            if d.as_str() == s {
                return Ok(d);
            }
        }
        Err(Error::invalid("unknown canonical domain"))
    }
}
/// Closed validated projection, never arbitrary domain strings or unchecked payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalProjection {
    domain: Domain,
    payload: V,
}
impl CanonicalProjection {
    pub fn from_payload(domain: Domain, payload: V) -> Result<Self> {
        crate::projection::validate(domain, &payload)?;
        Ok(Self { domain, payload })
    }
    pub fn read(bytes: &[u8], limits: Limits) -> Result<Self> {
        let v = V::parse(bytes, limits)?;
        v.closed(&["domain", "version", "payload"], &[])?;
        if v.field("version")?.as_str()? != "ctxql-canonical/v1" {
            return Err(Error::invalid("canonical version"));
        }
        Self::from_payload(
            Domain::parse(v.field("domain")?.as_str()?)?,
            v.field("payload")?.clone(),
        )
    }
    pub fn domain(&self) -> Domain {
        self.domain
    }
    pub fn payload(&self) -> &V {
        &self.payload
    }
    pub fn envelope(&self) -> V {
        obj([
            ("domain", V::string(self.domain.as_str())),
            ("version", V::string("ctxql-canonical/v1")),
            ("payload", self.payload.clone()),
        ])
    }
    pub fn bytes(&self, limits: Limits) -> Result<Vec<u8>> {
        self.envelope().canonical_bytes(limits)
    }
    pub fn hash(&self, limits: Limits) -> Result<ContentHash> {
        Ok(ContentHash::of_bytes(&self.bytes(limits)?))
    }
}
