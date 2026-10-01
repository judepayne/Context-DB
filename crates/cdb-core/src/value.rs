use crate::limits::Budget;
use crate::{Error, ExactNumber, Limits, Result};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalValue {
    Null,
    Bool(bool),
    Number(ExactNumber),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lookup<'a> {
    Missing,
    Present(&'a CanonicalValue),
}
impl CanonicalValue {
    pub fn parse(input: &[u8], limits: Limits) -> Result<Self> {
        if input.len() > limits.input_bytes() {
            return Err(Error::limit());
        }
        let text = std::str::from_utf8(input).map_err(|_| Error::invalid("UTF-8"))?;
        // Check container nesting without recursion/allocation before descending.
        let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
        for b in input {
            if quoted {
                if escaped {
                    escaped = false;
                } else if *b == b'\\' {
                    escaped = true;
                } else if *b == b'"' {
                    quoted = false;
                }
            } else {
                match b {
                    b'"' => quoted = true,
                    b'[' | b'{' => {
                        depth += 1;
                        if depth > limits.depth() {
                            return Err(Error::limit());
                        }
                    }
                    b']' | b'}' => depth = depth.saturating_sub(1),
                    _ => (),
                }
            }
        }
        let mut p = Parser {
            text,
            pos: 0,
            budget: Budget::new(limits),
            limits,
        };
        p.budget.charge(0, input.len(), input.len())?;
        let value = p.value(0)?;
        p.ws();
        if p.pos != text.len() {
            return Err(Error::invalid("trailing JSON"));
        }
        Ok(value)
    }
    pub fn object(entries: impl IntoIterator<Item = (String, Self)>) -> Result<Self> {
        let mut out = BTreeMap::new();
        for (k, v) in entries {
            if out.insert(k, v).is_some() {
                return Err(Error::invalid("duplicate object key"));
            }
        }
        Ok(Self::Object(out))
    }
    pub fn string(s: impl Into<String>) -> Self {
        Self::String(s.into())
    }
    pub fn integer(n: u64) -> Self {
        Self::Number(ExactNumber::from_u64(n))
    }
    pub fn as_object(&self) -> Result<&BTreeMap<String, Self>> {
        if let Self::Object(v) = self {
            Ok(v)
        } else {
            Err(Error::invalid("expected object"))
        }
    }
    pub fn as_array(&self) -> Result<&[Self]> {
        if let Self::Array(v) = self {
            Ok(v)
        } else {
            Err(Error::invalid("expected array"))
        }
    }
    pub fn as_str(&self) -> Result<&str> {
        if let Self::String(v) = self {
            Ok(v)
        } else {
            Err(Error::invalid("expected string"))
        }
    }
    pub fn as_bool(&self) -> Result<bool> {
        if let Self::Bool(v) = self {
            Ok(*v)
        } else {
            Err(Error::invalid("expected boolean"))
        }
    }
    pub fn as_number(&self) -> Result<&ExactNumber> {
        if let Self::Number(v) = self {
            Ok(v)
        } else {
            Err(Error::invalid("expected number"))
        }
    }
    pub fn u64(&self) -> Result<u64> {
        self.as_number()?.to_u64()
    }
    pub fn field(&self, key: &str) -> Result<&Self> {
        self.as_object()?
            .get(key)
            .ok_or_else(|| Error::invalid(format!("missing field {key}")))
    }
    pub fn lookup(&self, key: &str) -> Result<Lookup<'_>> {
        Ok(match self.as_object()?.get(key) {
            Some(v) => Lookup::Present(v),
            None => Lookup::Missing,
        })
    }
    pub fn closed(&self, required: &[&str], optional: &[&str]) -> Result<()> {
        let o = self.as_object()?;
        for k in required {
            if !o.contains_key(*k) {
                return Err(Error::invalid(format!("missing field {k}")));
            }
        }
        for k in o.keys() {
            if !required.contains(&k.as_str()) && !optional.contains(&k.as_str()) {
                return Err(Error::invalid(format!("unknown field {k}")));
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self, limits: Limits) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut budget = Budget::new(limits);
        self.emit(&mut out, limits, &mut budget, 0)?;
        Ok(out)
    }
    fn emit(
        &self,
        out: &mut Vec<u8>,
        limits: Limits,
        budget: &mut Budget,
        depth: usize,
    ) -> Result<()> {
        // Match parser preflight: depth counts containers, including empty ones.
        if depth > limits.depth()
            || (matches!(self, Self::Array(_) | Self::Object(_)) && depth >= limits.depth())
        {
            return Err(Error::limit());
        }
        budget.charge(1, 1, 0)?;
        fn put(out: &mut Vec<u8>, s: &str, l: Limits) -> Result<()> {
            if out.len().checked_add(s.len()).ok_or_else(Error::limit)? > l.output_bytes() {
                return Err(Error::limit());
            }
            out.extend_from_slice(s.as_bytes());
            Ok(())
        }
        fn string(out: &mut Vec<u8>, s: &str, l: Limits) -> Result<()> {
            put(out, "\"", l)?;
            for c in s.chars() {
                match c {
                    '"' => put(out, "\\\"", l)?,
                    '\\' => put(out, "\\\\", l)?,
                    '\u{8}' => put(out, "\\b", l)?,
                    '\t' => put(out, "\\t", l)?,
                    '\n' => put(out, "\\n", l)?,
                    '\u{c}' => put(out, "\\f", l)?,
                    '\r' => put(out, "\\r", l)?,
                    c if c < ' ' => put(out, &format!("\\u{:04x}", c as u32), l)?,
                    c => {
                        let mut b = [0; 4];
                        put(out, c.encode_utf8(&mut b), l)?;
                    }
                }
            }
            put(out, "\"", l)
        }
        match self {
            Self::Null => put(out, "null", limits)?,
            Self::Bool(b) => put(out, if *b { "true" } else { "false" }, limits)?,
            Self::Number(n) => put(out, &n.token(), limits)?,
            Self::String(s) => {
                budget.charge(0, s.len(), 0)?;
                string(out, s, limits)?;
            }
            Self::Array(a) => {
                put(out, "[", limits)?;
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        put(out, ",", limits)?;
                    }
                    v.emit(out, limits, budget, depth + 1)?;
                }
                put(out, "]", limits)?;
            }
            Self::Object(o) => {
                put(out, "{", limits)?;
                for (i, (k, v)) in o.iter().enumerate() {
                    if i > 0 {
                        put(out, ",", limits)?;
                    }
                    budget.charge(0, k.len(), 0)?;
                    string(out, k, limits)?;
                    put(out, ":", limits)?;
                    v.emit(out, limits, budget, depth + 1)?;
                }
                put(out, "}", limits)?;
            }
        }
        Ok(())
    }
}
struct Parser<'a> {
    text: &'a str,
    pos: usize,
    budget: Budget,
    limits: Limits,
}
impl Parser<'_> {
    fn ws(&mut self) {
        while self
            .text
            .as_bytes()
            .get(self.pos)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.pos += 1;
        }
    }
    fn string(&mut self) -> Result<String> {
        let start = self.pos;
        self.pos += 1;
        let mut escape = false;
        while let Some(b) = self.text.as_bytes().get(self.pos) {
            self.pos += 1;
            if escape {
                escape = false;
            } else if *b == b'\\' {
                escape = true;
            } else if *b == b'"' {
                let s = &self.text[start..self.pos];
                self.budget.charge(0, s.len(), 0)?;
                return serde_json::from_str::<String>(s)
                    .map_err(|_| Error::invalid("JSON string"));
            }
        }
        Err(Error::invalid("unterminated string"))
    }
    fn value(&mut self, depth: usize) -> Result<CanonicalValue> {
        self.ws();
        if depth > self.limits.depth() {
            return Err(Error::limit());
        }
        self.budget.charge(1, 1, 0)?;
        let b = *self
            .text
            .as_bytes()
            .get(self.pos)
            .ok_or_else(|| Error::invalid("missing value"))?;
        let v =
            match b {
                b'"' => CanonicalValue::String(self.string()?),
                b'{' => {
                    self.pos += 1;
                    self.ws();
                    let mut o = BTreeMap::new();
                    if self.text.as_bytes().get(self.pos) != Some(&b'}') {
                        loop {
                            self.ws();
                            if self.text.as_bytes().get(self.pos) != Some(&b'"') {
                                return Err(Error::invalid("object key"));
                            }
                            let k = self.string()?;
                            if o.contains_key(&k) {
                                return Err(Error::invalid("duplicate decoded key"));
                            }
                            self.ws();
                            self.take(b':')?;
                            let v = self.value(depth + 1)?;
                            o.insert(k, v);
                            self.ws();
                            if self.text.as_bytes().get(self.pos) == Some(&b'}') {
                                break;
                            }
                            self.take(b',')?;
                        }
                    }
                    self.take(b'}')?;
                    CanonicalValue::Object(o)
                }
                b'[' => {
                    self.pos += 1;
                    self.ws();
                    let mut a = Vec::new();
                    if self.text.as_bytes().get(self.pos) != Some(&b']') {
                        loop {
                            a.push(self.value(depth + 1)?);
                            self.ws();
                            if self.text.as_bytes().get(self.pos) == Some(&b']') {
                                break;
                            }
                            self.take(b',')?;
                        }
                    }
                    self.take(b']')?;
                    CanonicalValue::Array(a)
                }
                b'n' => {
                    self.word("null")?;
                    CanonicalValue::Null
                }
                b't' => {
                    self.word("true")?;
                    CanonicalValue::Bool(true)
                }
                b'f' => {
                    self.word("false")?;
                    CanonicalValue::Bool(false)
                }
                b'-' | b'0'..=b'9' => {
                    let start = self.pos;
                    while self.text.as_bytes().get(self.pos).is_some_and(|b| {
                        matches!(b, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                    }) {
                        self.pos += 1;
                    }
                    let s = &self.text[start..self.pos];
                    self.budget.charge(0, s.len(), 0)?;
                    CanonicalValue::Number(ExactNumber::parse(s)?)
                }
                _ => return Err(Error::invalid("JSON value")),
            };
        Ok(v)
    }
    fn take(&mut self, b: u8) -> Result<()> {
        if self.text.as_bytes().get(self.pos) != Some(&b) {
            return Err(Error::invalid("JSON punctuation"));
        }
        self.pos += 1;
        Ok(())
    }
    fn word(&mut self, s: &str) -> Result<()> {
        if !self.text[self.pos..].starts_with(s) {
            return Err(Error::invalid("JSON keyword"));
        }
        self.pos += s.len();
        Ok(())
    }
}
/// Small construction helper; keys are statically unique at call sites.
pub(crate) fn obj<const N: usize>(fields: [(&str, CanonicalValue); N]) -> CanonicalValue {
    CanonicalValue::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}
