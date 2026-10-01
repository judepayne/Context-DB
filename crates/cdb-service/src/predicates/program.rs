//! Pre-optimization analysis of validated, lowered Rhai 1.26 source.
//! This is not a source validator: the lowerer must reserve internal identifiers
//! and the engine must disable reflection/ambient facilities before calling here.
use rhai::{ASTNode, Engine, Expr, FnCallExpr, OptimizationLevel, Stmt, AST};
#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub source_bytes: usize,
    pub nodes: usize,
    pub depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            source_bytes: 262_144,
            nodes: 16_384,
            depth: 128,
        }
    }
}

#[derive(Debug)]
pub struct Analysis {
    pub ast: AST,
    pub free_variables: BTreeSet<String>,
    pub nodes: usize,
}

pub fn reserved(name: &str) -> bool {
    name.starts_with("ctxql_internal_")
        || matches!(
            name,
            "state" | "next" | "eval" | "Fn" | "import" | "export" | "print" | "debug"
        )
}

struct Visitor {
    locals: BTreeSet<String>,
    free: BTreeSet<String>,
}
impl Visitor {
    fn bind(&mut self, name: &str) -> Result<(), String> {
        if reserved(name) && name != "ctxql_internal_catch_error" {
            return Err(format!("reserved local binding: {name}"));
        }
        self.locals.insert(name.into());
        Ok(())
    }
    fn variable(&mut self, name: &str) {
        if !self.locals.contains(name) {
            self.free.insert(name.into());
        }
    }
    fn block<'a>(&mut self, stmts: impl IntoIterator<Item = &'a Stmt>) -> Result<(), String> {
        let saved = self.locals.clone();
        for stmt in stmts {
            self.stmt(stmt)?;
        }
        self.locals = saved;
        Ok(())
    }
    fn call(&mut self, call: &FnCallExpr) -> Result<(), String> {
        if call.name == "ctxql_internal_external" && !(1..=16).contains(&call.args.len()) {
            return Err("callback requires a name and at most fifteen arguments".into());
        }
        for arg in &call.args {
            self.expr(arg)?;
        }
        Ok(())
    }
    fn expr(&mut self, expr: &Expr) -> Result<(), String> {
        match expr {
            Expr::Variable(v, ..) => {
                if !v.2.is_empty() {
                    return Err("qualified variable is unsupported".into());
                }
                self.variable(v.1.as_str());
            }
            Expr::IntegerConstant(..) | Expr::DynamicConstant(..) => (),
            Expr::Array(items, ..) | Expr::InterpolatedString(items, ..) => {
                for item in items {
                    self.expr(item)?;
                }
            }
            Expr::And(items, ..) | Expr::Or(items, ..) | Expr::Coalesce(items, ..) => {
                for item in items.iter() {
                    self.expr(item)?;
                }
            }
            Expr::Map(map, ..) => {
                for (_, value) in &map.0 {
                    self.expr(value)?;
                }
            }
            Expr::Stmt(block) => self.block(block.iter())?,
            Expr::FnCall(call, ..) | Expr::MethodCall(call, ..) => self.call(call)?,
            Expr::Dot(pair, ..) | Expr::Index(pair, ..) => {
                self.expr(&pair.lhs)?;
                self.expr(&pair.rhs)?;
            }
            Expr::ThisPtr(..) => self.variable("this"),
            Expr::BoolConstant(..)
            | Expr::CharConstant(..)
            | Expr::StringConstant(..)
            | Expr::Unit(..)
            | Expr::Property(..) => (),
            _ => return Err("unsupported AST expression".into()),
        }
        Ok(())
    }
    fn stmt(&mut self, stmt: &Stmt) -> Result<(), String> {
        match stmt {
            Stmt::Var(v, ..) => {
                self.expr(&v.1)?;
                self.bind(v.0.name.as_str())?;
            }
            Stmt::If(flow, ..) | Stmt::While(flow, ..) | Stmt::Do(flow, ..) => {
                self.expr(&flow.expr)?;
                self.block(flow.body.iter())?;
                self.block(flow.branch.iter())?;
            }
            Stmt::For(data, ..) => {
                self.expr(&data.2.expr)?;
                let saved = self.locals.clone();
                self.bind(data.0.name.as_str())?;
                if let Some(counter) = &data.1 {
                    self.bind(counter.name.as_str())?;
                }
                self.block(data.2.body.iter())?;
                self.locals = saved;
                self.block(data.2.branch.iter())?;
            }
            Stmt::TryCatch(flow, ..) => {
                self.block(flow.body.iter())?;
                let saved = self.locals.clone();
                match &flow.expr {
                    Expr::Variable(v, ..) => self.bind(v.1.as_str())?,
                    Expr::Unit(..) => (),
                    _ => return Err("unexpected catch binding AST".into()),
                }
                self.block(flow.branch.iter())?;
                self.locals = saved;
            }
            Stmt::Switch(data, ..) => {
                self.expr(&data.0)?;
                for pair in &data.1.expressions {
                    self.expr(&pair.lhs)?;
                    self.expr(&pair.rhs)?;
                }
            }
            Stmt::Assignment(data) => {
                self.expr(&data.1.lhs)?;
                self.expr(&data.1.rhs)?;
            }
            Stmt::FnCall(call, ..) => self.call(call)?,
            Stmt::Block(block) => self.block(block.iter())?,
            Stmt::Expr(expr) => self.expr(expr)?,
            Stmt::Return(expr, ..) | Stmt::BreakLoop(expr, ..) => {
                if let Some(expr) = expr {
                    self.expr(expr)?;
                }
            }
            Stmt::Share(vars) => {
                for (name, _) in vars.iter() {
                    self.variable(name.name.as_str());
                }
            }
            Stmt::Noop(..) => (),
            _ => return Err("unsupported AST statement".into()),
        }
        Ok(())
    }
}

pub fn analyze(engine: &Engine, lowered: &str, limits: Limits) -> Result<Analysis, String> {
    if engine.optimization_level() != OptimizationLevel::None {
        return Err("dependency analysis requires OptimizationLevel::None".into());
    }
    if lowered.len() > limits.source_bytes {
        return Err("source budget".into());
    }
    let ast = engine.compile(lowered).map_err(|e| e.to_string())?;
    let mut nodes = 0;
    // Bound the actual walker before the recursive scope traversal. Function
    // bodies are included; container/property names are not fabricated nodes.
    let complete = ast.walk(&mut |path| {
        nodes += 1;
        nodes <= limits.nodes && path.len() <= limits.depth
    });
    if !complete {
        return Err("AST node/depth budget".into());
    }
    let mut visitor = Visitor {
        locals: BTreeSet::new(),
        free: BTreeSet::new(),
    };
    for stmt in ast.statements() {
        visitor.stmt(stmt)?;
    }
    // Public internals do not export ScriptFuncPayload. Walk one filtered
    // function AST at a time, handling only root statements ourselves.
    for metadata in ast.iter_functions() {
        if reserved(metadata.name) {
            return Err(format!("reserved function: {}", metadata.name));
        }
        visitor.locals.clear();
        for param in &metadata.params {
            visitor.bind(param)?;
        }
        // Pinned Rhai merge_filtered clones all functions when the destination
        // map is empty. Explicit retain avoids analyzing other bodies with the
        // wrong parameter scope.
        let mut function = ast.clone_functions_only();
        function.retain_functions(|_, _, name, arity| {
            name == metadata.name && arity == metadata.params.len()
        });
        let mut result = Ok(());
        function.walk(&mut |path| {
            if path.len() == 1 {
                if let ASTNode::Stmt(stmt) = path[0] {
                    result = visitor.stmt(stmt);
                }
            }
            result.is_ok()
        });
        result?;
    }
    Ok(Analysis {
        ast,
        free_variables: visitor.free,
        nodes,
    })
}

/// `bindings` is the complete pre-evaluation environment (including `state`
/// when present). Do not include staged NEXT keys: each next expression must
/// instead be independently checked against this environment plus prepared LETs.
#[cfg(test)]
pub fn prepare_lets(
    engine: &Engine,
    expressions: &BTreeMap<String, String>,
    bindings: &BTreeSet<String>,
) -> Result<Vec<String>, String> {
    let limits = Limits::default();
    if expressions.len() > 256 {
        return Err("expression count budget".into());
    }
    for name in bindings {
        // `state` is the one host-owned reserved environment binding.
        if name != "state" && reserved(name) {
            return Err(format!("reserved environment binding: {name}"));
        }
    }
    let mut bytes = 0usize;
    let mut nodes = 0usize;
    let mut dependencies = BTreeMap::new();
    for (name, source) in expressions {
        if reserved(name) || bindings.contains(name) {
            return Err(format!("LET binding collision: {name}"));
        }
        bytes = bytes.checked_add(source.len()).ok_or("source budget")?;
        if bytes > limits.source_bytes {
            return Err("source budget".into());
        }
        let analysis = analyze(engine, source, limits)?;
        nodes += analysis.nodes;
        if nodes > limits.nodes {
            return Err("AST node budget".into());
        }
        let mut deps = BTreeSet::new();
        for free in analysis.free_variables {
            if expressions.contains_key(&free) {
                deps.insert(free);
            } else if !bindings.contains(&free) {
                return Err(format!("unknown dependency in {name}: {free}"));
            }
        }
        dependencies.insert(name.clone(), deps);
    }
    let mut ordered = Vec::new();
    while !dependencies.is_empty() {
        let Some(name) = dependencies
            .iter()
            .find(|(_, deps)| deps.is_empty())
            .map(|(name, _)| name.clone())
        else {
            return Err("LET dependency cycle".into());
        };
        dependencies.remove(&name);
        for deps in dependencies.values_mut() {
            deps.remove(&name);
        }
        ordered.push(name);
    }
    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn engine() -> Engine {
        let mut e = Engine::new();
        e.set_optimization_level(OptimizationLevel::None);
        e
    }
    fn free(code: &str) -> BTreeSet<String> {
        analyze(&engine(), code, Limits::default())
            .unwrap()
            .free_variables
    }
    fn names(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn lexical_names_and_scopes() {
        assert_eq!(
            free("let x = outer; { const outer = true; outer; } #{key: x}.key; \"unknown\""),
            names(&["outer"])
        );
        assert_eq!(free("let x = x; { let y = x; } y"), names(&["x", "y"]));
        assert_eq!(
            free("for x in input { x; } try { input; } catch (err) { err; }"),
            names(&["input"])
        );
        assert_eq!(
            free("fn f(x) { let y = x; y } let c = |z| z + outside; f(input)"),
            names(&["outside", "input"])
        );
    }
    #[test]
    fn dependencies_and_isolation() {
        let e = engine();
        let mut lets = BTreeMap::from([
            ("b".into(), "a".into()),
            ("a".into(), "state.value".into()),
            ("λ".into(), "true".into()),
        ]);
        assert_eq!(
            prepare_lets(&e, &lets, &names(&["state"])).unwrap(),
            ["a", "b", "λ"]
        );
        lets.insert("a".into(), "b".into());
        assert!(prepare_lets(&e, &lets, &names(&["state"]))
            .unwrap_err()
            .contains("cycle"));
        lets.insert("a".into(), "next_value".into());
        assert!(prepare_lets(&e, &lets, &names(&["state"]))
            .unwrap_err()
            .contains("unknown"));
        assert_eq!(
            free("if false { dead_dependency } else { true }"),
            names(&["dead_dependency"])
        );
    }
    #[test]
    fn budgets_and_native_counter_scope() {
        let e = engine();
        let a = analyze(
            &e,
            "for (x, counter) in input { counter; }",
            Limits::default(),
        )
        .unwrap();
        assert_eq!(a.free_variables, names(&["input"]));
        assert!(analyze(
            &e,
            "[[[[true]]]]",
            Limits {
                depth: 2,
                ..Limits::default()
            }
        )
        .is_err());
        assert!(analyze(
            &e,
            "[true, false]",
            Limits {
                nodes: 2,
                ..Limits::default()
            }
        )
        .is_err());
        assert!(analyze(
            &e,
            "true",
            Limits {
                source_bytes: 3,
                ..Limits::default()
            }
        )
        .is_err());
        assert!(analyze(&e, "let ctxql_internal_num = true;", Limits::default()).is_err());
        let mut optimized = engine();
        optimized.set_optimization_level(OptimizationLevel::Full);
        assert!(analyze(&optimized, "true", Limits::default()).is_err());
    }
}
