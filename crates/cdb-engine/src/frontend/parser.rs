use super::{SourceMap, SourceSpan};
use crate::artifacts::{ArtifactKind, ArtifactName};
use cdb_core::{CanonicalValue as V, Error, Limits, Result};
use std::collections::BTreeMap;
type Object = BTreeMap<String, V>;
struct Line<'a> {
    indent: usize,
    text: &'a str,
    span: SourceSpan,
}
struct Parser<'a, 'm> {
    lines: Vec<Line<'a>>,
    pos: usize,
    limits: Limits,
    map: &'m mut SourceMap,
}
fn invalid() -> Error {
    Error::invalid("text-language/v1 syntax or duplicate clause")
}
fn put(o: &mut Object, key: &str, v: V) -> Result<()> {
    if o.insert(key.to_owned(), v).is_some() {
        return Err(invalid());
    }
    Ok(())
}
fn pointer(path: &str, key: &str) -> String {
    format!("{}/{}", path, key.replace('~', "~0").replace('/', "~1"))
}
// Comments are stripped only in structural/literal contexts, never expressions.
fn uncomment(s: &str) -> &str {
    let (mut quote, mut escape) = (false, false);
    for (i, c) in s.char_indices() {
        if quote {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                quote = false;
            }
        } else if c == '"' {
            quote = true;
        } else if (c == '#' || s[i..].starts_with("//"))
            && (i == 0 || s.as_bytes()[i - 1].is_ascii_whitespace())
        {
            return s[..i].trim_end();
        }
    }
    s.trim_end()
}
fn value(s: &str, l: Limits) -> Result<V> {
    let s = uncomment(s).trim();
    if s.is_empty() {
        return Err(invalid());
    }
    if s.starts_with(['"', '[', '{', '-'])
        || s.as_bytes()[0].is_ascii_digit()
        || matches!(s, "true" | "false" | "null")
    {
        V::parse(s.as_bytes(), l)
    } else if !s.chars().any(char::is_whitespace) {
        Ok(V::string(s))
    } else {
        Err(invalid())
    }
}
fn assignment(s: &str) -> Result<(&str, &str)> {
    let (key, v) = s.split_once('=').ok_or_else(invalid)?;
    let key = key.trim();
    let v = v.trim();
    if key.is_empty() || key.chars().any(char::is_whitespace) || v.is_empty() {
        return Err(invalid());
    }
    Ok((key, v))
}
fn triple(s: &str, l: Limits) -> Result<V> {
    let s = uncomment(s);
    let split = s.find(char::is_whitespace).ok_or_else(invalid)?;
    let field = &s[..split];
    let rest = s[split..].trim_start();
    let split = rest.find(char::is_whitespace).ok_or_else(invalid)?;
    Ok(V::Array(vec![
        V::string(field),
        V::string(&rest[..split]),
        value(rest[split..].trim(), l)?,
    ]))
}
// Consume one JSON string/container or one bare token without splitting quoted
// keywords, nested values or escaped strings.
fn token(s: &str) -> Result<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return Err(invalid());
    }
    let (mut quoted, mut escape, mut depth) = (false, false, 0usize);
    for (i, c) in s.char_indices() {
        if quoted {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                quoted = false;
            }
        } else {
            match c {
                '"' => quoted = true,
                '[' | '{' => depth += 1,
                ']' | '}' => depth = depth.checked_sub(1).ok_or_else(invalid)?,
                _ => (),
            }
            if c.is_whitespace() && depth == 0 {
                return Ok((&s[..i], s[i..].trim_start()));
            }
        }
    }
    if quoted || depth != 0 {
        return Err(invalid());
    }
    Ok((s, ""))
}
fn about(s: &str, l: Limits) -> Result<V> {
    let mut o = Object::new();
    let mut rest = s;
    for key in ["FROM", "TO", "MATCH"] {
        if let Some(tail) = rest.strip_prefix(key).filter(|s| s.starts_with(' ')) {
            let (t, r) = token(tail)?;
            rest = r;
            let mut v = value(t, l)?;
            if key != "MATCH" && !matches!(v, V::Array(_)) {
                v = V::Array(vec![v]);
            }
            put(&mut o, &key.to_ascii_lowercase(), v)?;
        }
    }
    if !rest.is_empty() || !o.contains_key("from") {
        return Err(invalid());
    }
    Ok(V::Object(o))
}
pub(super) fn parse(
    kind: ArtifactKind,
    text: &str,
    base: usize,
    limits: Limits,
    map: &mut SourceMap,
) -> Result<V> {
    let mut lines = Vec::new();
    let mut offset = base;
    for raw in text.split_inclusive(['\r', '\n']) {
        let line = raw.trim_end_matches(['\r', '\n']);
        let trimmed = line.trim_start_matches(' ');
        if line.contains('\t') {
            return Err(invalid());
        }
        if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with("//") {
            let indent = line.len() - trimmed.len();
            if indent % 2 != 0 || indent / 2 > limits.depth() || lines.len() >= limits.values() {
                return Err(invalid());
            }
            lines.push(Line {
                indent,
                text: trimmed,
                span: SourceSpan {
                    start: offset + indent,
                    end: offset + line.len(),
                },
            });
        }
        offset += raw.len();
    }
    let mut p = Parser {
        lines,
        pos: 0,
        limits,
        map,
    };
    let expected = if kind == ArtifactKind::Query {
        "QUERY"
    } else {
        "PROFILE"
    };
    if p.lines
        .first()
        .is_none_or(|l| l.indent != 0 || l.text != expected)
    {
        return Err(invalid());
    }
    p.map.insert(
        "",
        SourceSpan {
            start: base,
            end: base + text.len(),
        },
        limits,
    )?;
    p.pos = 1;
    let mut root = Object::new();
    while p.pos < p.lines.len() {
        let line = &p.lines[p.pos];
        if line.indent != 0 {
            return Err(invalid());
        }
        let s = uncomment(line.text);
        let span = line.span;
        p.pos += 1;
        let (key, v) = if let Some(name) = s.strip_prefix("NAME ") {
            if kind != ArtifactKind::Profile {
                return Err(invalid());
            }
            ArtifactName::new(name, limits.input_bytes())?;
            ("name", V::string(name))
        } else if let Some(name) = s.strip_prefix("USE PROFILE ") {
            ArtifactName::new(name, limits.input_bytes())?;
            ("profile", V::string(name))
        } else {
            match s {
                "CONTEXT" => ("@context", p.assignments(2, "/@context", false, false)?),
                "BOUNDS" => ("bounds", p.assignments(2, "/bounds", false, false)?),
                "RETURN" => ("return", p.returns()?),
                "ABOUT" => {
                    let mut a = Vec::new();
                    while p.at(2) {
                        let i = a.len();
                        let l = &p.lines[p.pos];
                        a.push(about(uncomment(l.text), limits)?);
                        p.map.insert(&format!("/about/{i}"), l.span, limits)?;
                        p.pos += 1;
                    }
                    ("about", V::Array(a))
                }
                "FILTER" => ("filter", p.phase("/filter", None)?),
                "WALK" => ("walk", p.phase("/walk", None)?),
                _ if s.starts_with("WALK ") => ("walk", p.phase("/walk", Some(s[5..].trim()))?),
                _ => return Err(invalid()),
            }
        };
        p.map.insert(&pointer("", key), span, limits)?;
        put(&mut root, key, v)?;
    }
    Ok(V::Object(root))
}
impl Parser<'_, '_> {
    fn at(&self, indent: usize) -> bool {
        self.lines.get(self.pos).is_some_and(|l| l.indent == indent)
    }
    fn assignments(&mut self, indent: usize, path: &str, expr: bool, literal: bool) -> Result<V> {
        let mut o = Object::new();
        while self.at(indent) {
            let l = &self.lines[self.pos];
            let (k, s) = assignment(l.text)?;
            let v = if expr {
                V::string(s)
            } else if literal {
                V::parse(uncomment(s).as_bytes(), self.limits)?
            } else {
                value(s, self.limits)?
            };
            put(&mut o, k, v)?;
            self.map.insert(&pointer(path, k), l.span, self.limits)?;
            self.pos += 1;
        }
        Ok(V::Object(o))
    }
    fn returns(&mut self) -> Result<V> {
        let mut o = Object::new();
        while self.at(2) {
            let l = &self.lines[self.pos];
            let s = uncomment(l.text);
            let (key, v) = if s.contains('=') {
                let (k, v) = assignment(s)?;
                (k, value(v, self.limits)?)
            } else {
                (s, V::Bool(true))
            };
            v.as_bool()?;
            put(&mut o, key, v)?;
            self.map
                .insert(&pointer("/return", key), l.span, self.limits)?;
            self.pos += 1;
        }
        Ok(V::Object(o))
    }
    fn phase(&mut self, path: &str, direction: Option<&str>) -> Result<V> {
        let mut o = Object::new();
        let mut predicates = Vec::new();
        let mut clear = false;
        if let Some(d) = direction {
            put(&mut o, "direction", V::string(d))?;
        }
        while self.at(2) {
            let l = &self.lines[self.pos];
            let s = uncomment(l.text);
            let span = l.span;
            self.pos += 1;
            if s == "PREDICATES []" {
                if clear || !predicates.is_empty() {
                    return Err(invalid());
                }
                clear = true;
            } else if let Some(d) = s.strip_prefix("DROP PREDICATES ") {
                let v = value(d, self.limits)?;
                v.as_array()?;
                put(&mut o, "drop_predicates", v)?;
            } else if s == "WHERE" {
                if clear {
                    return Err(invalid());
                }
                let before = predicates.len();
                while self.at(4) {
                    let l = &self.lines[self.pos];
                    self.map.insert(
                        &format!("{path}/predicates/{}", predicates.len()),
                        l.span,
                        self.limits,
                    )?;
                    predicates.push(triple(l.text, self.limits)?);
                    self.pos += 1;
                }
                if predicates.len() == before {
                    return Err(invalid());
                }
            } else if let Some(name) = s.strip_prefix("PREDICATE ") {
                if clear || name.is_empty() {
                    return Err(invalid());
                }
                let pp = format!("{path}/predicates/{}", predicates.len());
                self.map.insert(&pp, span, self.limits)?;
                predicates.push(self.predicate(name, &pp)?);
            } else {
                return Err(invalid());
            }
        }
        if clear || !predicates.is_empty() {
            put(&mut o, "predicates", V::Array(predicates))?;
        }
        Ok(V::Object(o))
    }
    fn predicate(&mut self, name: &str, path: &str) -> Result<V> {
        let mut o = Object::new();
        put(&mut o, "name", V::string(name))?;
        while self.at(4) {
            let l = &self.lines[self.pos];
            let raw = l.text;
            let span = l.span;
            self.pos += 1;
            let (key, v) = if let Some(expr) = raw.strip_prefix("KEEP ") {
                if expr.trim().is_empty() {
                    return Err(invalid());
                }
                ("keep", V::string(expr))
            } else {
                match uncomment(raw) {
                    "INIT" => (
                        "init",
                        self.assignments(6, &pointer(path, "init"), false, true)?,
                    ),
                    "BIND" => (
                        "bind",
                        self.assignments(6, &pointer(path, "bind"), false, false)?,
                    ),
                    "LET" => (
                        "let",
                        self.assignments(6, &pointer(path, "let"), true, false)?,
                    ),
                    "NEXT" => (
                        "next",
                        self.assignments(6, &pointer(path, "next"), true, false)?,
                    ),
                    "WHERE" => {
                        if !self.at(6) {
                            return Err(invalid());
                        }
                        let v = triple(self.lines[self.pos].text, self.limits)?;
                        self.pos += 1;
                        ("where", v)
                    }
                    _ => return Err(invalid()),
                }
            };
            self.map.insert(&pointer(path, key), span, self.limits)?;
            put(&mut o, key, v)?;
        }
        Ok(V::Object(o))
    }
}
