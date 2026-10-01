//! Callback-only token adaptation. Numeric source is copied unchanged.
use rhai::{ASTNode, Engine, Expr, OptimizationLevel, Stmt};
use std::collections::BTreeMap;

pub const SOURCE_BUDGET: usize = 16_384;
pub const LOWERED_BUDGET: usize = 262_144;
pub const TOKEN_BUDGET: usize = 16_384;
pub const DEPTH_BUDGET: usize = 64;

#[derive(Debug, Clone)]
pub struct Lowered {
    pub source: String,
    /// One original byte offset per output byte; inserted bytes point at the
    /// opening source token. There is no extra EOF entry.
    pub origins: Vec<usize>,
}
impl Lowered {
    fn insert(&mut self, text: &str, origin: usize) -> Result<(), String> {
        if self.source.len() + text.len() > LOWERED_BUDGET {
            return Err("lowered source budget".into());
        }
        self.source.push_str(text);
        self.origins.extend(std::iter::repeat_n(origin, text.len()));
        Ok(())
    }
    fn copy(&mut self, source: &str, start: usize, end: usize) -> Result<(), String> {
        self.insert(&source[start..end], start)?;
        let n = self.origins.len();
        for (offset, origin) in self.origins[n - (end - start)..].iter_mut().enumerate() {
            *origin = start + offset;
        }
        Ok(())
    }
}

struct Lexer<'a> {
    source: &'a str,
    at: usize,
    tokens: usize,
    external_tokens: usize,
    out: Lowered,
    // Bracket pairs in the intermediate output, not the authored source.
    brackets: BTreeMap<usize, usize>,
}
impl Lexer<'_> {
    fn rest(&self) -> &str {
        &self.source[self.at..]
    }
    fn bump(&mut self) {
        self.at += self.rest().chars().next().unwrap().len_utf8();
    }
    fn token(&mut self) -> Result<(), String> {
        self.tokens += 1;
        if self.tokens > TOKEN_BUDGET {
            Err("token budget".into())
        } else {
            Ok(())
        }
    }
    fn copy_from(&mut self, start: usize) -> Result<(), String> {
        self.out.copy(self.source, start, self.at)
    }
    fn comment(&mut self) -> Result<(), String> {
        let start = self.at;
        if self.rest().starts_with("//") {
            while self.at < self.source.len() && !self.rest().starts_with('\n') {
                self.bump();
            }
        } else {
            self.at += 2;
            let mut depth = 1;
            while depth > 0 {
                if self.at == self.source.len() {
                    return Err("unterminated comment".into());
                }
                if self.rest().starts_with("/*") {
                    depth += 1;
                    if depth > DEPTH_BUDGET {
                        return Err("comment depth budget".into());
                    }
                    self.at += 2;
                } else if self.rest().starts_with("*/") {
                    depth -= 1;
                    self.at += 2;
                } else {
                    self.bump();
                }
            }
        }
        self.copy_from(start)
    }
    // Rhai parse_string_literal doubles delimiters, including character
    // delimiters. Backticks are verbatim except for the special \${ escape.
    fn quoted(&mut self, quote: char, depth: usize) -> Result<(), String> {
        let mut start = self.at;
        self.bump();
        loop {
            if self.at == self.source.len() {
                return Err("unterminated quoted literal".into());
            }
            if quote == '`' && self.rest().starts_with("\\${") {
                self.at += 3;
            } else if quote == '`' && self.rest().starts_with("${") {
                self.at += 2;
                self.copy_from(start)?;
                self.code(Some('}'), depth + 1)?;
                start = self.at;
            } else {
                let c = self.rest().chars().next().unwrap();
                self.bump();
                if c == quote {
                    if self.rest().starts_with(quote) {
                        self.bump();
                    } else {
                        return self.copy_from(start);
                    }
                } else if c == '\\' && quote != '`' {
                    if self.at == self.source.len() {
                        return Err("unterminated escape".into());
                    }
                    // Consume a whole Unicode scalar, never half of a UTF-8
                    // sequence. Rhai validates escape spelling and char width
                    // in the sanitized compile below.
                    self.bump();
                } else if c == '\n' && quote != '`' {
                    return Err("newline in quoted literal".into());
                }
            }
        }
    }
    fn raw(&mut self) -> Result<(), String> {
        let start = self.at;
        while self.rest().starts_with('#') {
            self.at += 1;
        }
        let count = self.at - start;
        if !self.rest().starts_with('"') {
            return Err("invalid raw string delimiter".into());
        }
        self.at += 1;
        let end = format!("\"{}", "#".repeat(count));
        let offset = self.rest().find(&end).ok_or("unterminated raw string")?;
        self.at += offset + end.len();
        self.copy_from(start)
    }
    fn code(&mut self, close: Option<char>, depth: usize) -> Result<(), String> {
        if depth > DEPTH_BUDGET {
            return Err("source depth budget".into());
        }
        while self.at < self.source.len() {
            let start = self.at;
            let c = self.rest().chars().next().unwrap();
            if c.is_whitespace() {
                self.bump();
                self.copy_from(start)?;
                continue;
            }
            if self.rest().starts_with("//") || self.rest().starts_with("/*") {
                self.comment()?;
                continue;
            }
            self.token()?;
            if matches!(c, ')' | ']' | '}') {
                if close != Some(c) {
                    return Err("unmatched closing delimiter".into());
                }
                self.bump();
                self.copy_from(start)?;
                return Ok(());
            }
            match c {
                '"' | '\'' | '`' => self.quoted(c, depth)?,
                '#' if !self.rest().starts_with("#{") => self.raw()?,
                '(' | '[' | '{' | '#' => {
                    let open = if c == '#' {
                        self.at += 1;
                        '{'
                    } else {
                        c
                    };
                    let output_start = self.out.source.len();
                    self.bump();
                    self.copy_from(start)?;
                    self.code(
                        Some(match open {
                            '(' => ')',
                            '[' => ']',
                            _ => '}',
                        }),
                        depth + 1,
                    )?;
                    if open == '[' {
                        self.brackets
                            .insert(output_start, self.out.source.len() - 1);
                    }
                }
                c if c.is_alphabetic() || c == '_' => {
                    self.bump();
                    while self
                        .rest()
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_alphanumeric() || c == '_')
                    {
                        self.bump();
                    }
                    let name = &self.source[start..self.at];
                    if name.starts_with("ctxql_internal_")
                        || matches!(
                            name,
                            "eval" | "import" | "export" | "Fn" | "print" | "debug"
                        )
                    {
                        return Err(format!("reserved or ambient symbol at byte {start}"));
                    }
                    let before = self.out.source.trim_end();
                    let wildcard_catch = name == "_"
                        && before.ends_with('(')
                        && before[..before.len() - 1].trim_end().ends_with("catch");
                    if wildcard_catch {
                        self.out.insert("ctxql_internal_catch_error", start)?;
                    } else if name == "fn" && self.rest().starts_with(":external") {
                        self.at += ":external".len();
                        if self
                            .rest()
                            .chars()
                            .next()
                            .is_some_and(|c| c.is_alphanumeric() || c == '_')
                        {
                            return Err("invalid external symbol".into());
                        }
                        self.external_tokens += 1;
                        self.out.insert("ctxql_internal_external", start)?;
                    } else {
                        self.copy_from(start)?;
                    }
                }
                // Rhai does not support identifier escapes. Fail before any
                // possibility of interpreting an escaped reserved name.
                '\\' => return Err("identifier escapes are not supported by Rhai".into()),
                _ => {
                    self.bump();
                    self.copy_from(start)?;
                }
            }
        }
        if close.is_some() {
            Err("unclosed delimiter".into())
        } else {
            Ok(())
        }
    }
}

pub fn lower(source: &str) -> Result<Lowered, String> {
    if source.len() > SOURCE_BUDGET {
        return Err("source budget".into());
    }
    let mut lexer = Lexer {
        source,
        at: 0,
        tokens: 0,
        external_tokens: 0,
        out: Lowered {
            source: String::new(),
            origins: Vec::new(),
        },
        brackets: BTreeMap::new(),
    };
    lexer.code(None, 0)?;
    let intermediate = lexer.out;
    let mut engine = Engine::new();
    engine.set_optimization_level(OptimizationLevel::None);
    engine.set_max_expr_depths(DEPTH_BUDGET, DEPTH_BUDGET);
    engine.set_max_functions(64);
    // No callbacks are registered; compiling cannot execute authored effects.
    // In particular no numeric token from the original program reaches Rhai.
    let ast = engine
        .compile(&intermediate.source)
        .map_err(|e| format!("lowered Rhai syntax: {e}"))?;
    if ast.iter_functions().any(|f| {
        f.name.starts_with("ctxql_internal_")
            || f.params.iter().any(|p| p.starts_with("ctxql_internal_"))
    }) {
        return Err("reserved callback binding".into());
    }
    let mut nodes = 0;
    let mut external_calls = 0;
    ast.walk(&mut |path| {
        nodes += 1;
        match path.last() {
            Some(ASTNode::Expr(Expr::FnCall(call, _)))
            | Some(ASTNode::Stmt(Stmt::FnCall(call, _)))
                if call.name == "ctxql_internal_external" && call.namespace.is_empty() =>
            {
                external_calls += 1
            }
            _ => (),
        }
        nodes <= TOKEN_BUDGET
    });
    if external_calls != lexer.external_tokens {
        return Err(
            "external notation must be a direct callback call, not a binding or name escape".into(),
        );
    }
    if nodes > TOKEN_BUDGET {
        return Err("AST budget".into());
    }
    Ok(intermediate)
}
