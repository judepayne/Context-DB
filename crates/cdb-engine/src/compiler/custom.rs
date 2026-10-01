use super::{
    charge_value, compile_mapping, resolve_operand, FieldMapping, FieldRef, MappingCapabilities,
};
use crate::predicates::Program;
use cdb_core::{CanonicalValue as V, Error, Result};
use std::collections::{BTreeMap, BTreeSet};

const FIELD: &str = "field";
const CONSTANT: &str = "constant";

/// A graph-derived field or a literal value resolved once from query bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CustomBinding {
    Field(FieldRef, Option<FieldMapping>),
    Constant(V),
}

/// Portable custom-predicate IR. Native hosts validate the original expressions
/// and compile them to their own AST before execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomProgram {
    program: Program,
    bindings: BTreeMap<String, CustomBinding>,
}
impl CustomProgram {
    pub fn program(&self) -> &Program {
        &self.program
    }
    pub fn bindings(&self) -> &BTreeMap<String, CustomBinding> {
        &self.bindings
    }
    pub fn binding_names(&self) -> Vec<String> {
        self.bindings.keys().cloned().collect()
    }
}

fn variable(name: &str) -> Result<()> {
    let mut chars = name.chars();
    if !chars.next().is_some_and(|c| c == '_' || c.is_alphabetic())
        || !chars.all(|c| c == '_' || c.is_alphanumeric())
        || matches!(name, "state" | "next")
    {
        return Err(Error::invalid("custom predicate variable"));
    }
    Ok(())
}

fn strings(value: Option<&V>, section: &str) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    if let Some(value) = value {
        for (name, expression) in value.as_object()? {
            variable(name)?;
            let expression = expression.as_str()?;
            if expression.trim().is_empty() {
                return Err(Error::invalid(section));
            }
            result.insert(name.clone(), expression.to_owned());
        }
    }
    Ok(result)
}

pub(super) fn compile(
    value: &mut V,
    bounds: Option<&V>,
    mappings: &V,
    capabilities: MappingCapabilities,
    budget: &mut cdb_core::limits::Budget,
) -> Result<CustomProgram> {
    let object = value.as_object()?.clone();
    let mut init = BTreeMap::new();
    if let Some(values) = object.get("init") {
        for (name, value) in values.as_object()? {
            variable(name)?;
            charge_value(value, budget)?;
            init.insert(name.clone(), value.clone());
        }
    }
    let lets = strings(object.get("let"), "custom LET expression")?;
    let next = strings(object.get("next"), "custom NEXT expression")?;
    let keep = object
        .get("keep")
        .ok_or_else(|| Error::invalid("custom KEEP required"))?
        .as_str()?;
    if keep.trim().is_empty() {
        return Err(Error::invalid("custom KEEP expression"));
    }
    let mut locals = BTreeSet::new();
    for name in lets.keys() {
        locals.insert(name.as_str());
    }
    let mut bindings = BTreeMap::new();
    let mut normalized = BTreeMap::new();
    if let Some(values) = object.get("bind") {
        for (name, authored) in values.as_object()? {
            variable(name)?;
            if !locals.insert(name) {
                return Err(Error::invalid("custom binding/LET collision"));
            }
            let binding = if let Some(bounds) = bounds {
                let source = authored.as_str()?;
                if source.starts_with("bound:") {
                    let resolved =
                        resolve_operand(authored, bounds, &BTreeMap::new(), false, budget)?;
                    normalized.insert(name.clone(), marker(CONSTANT, resolved.clone()));
                    CustomBinding::Constant(resolved)
                } else {
                    let field = FieldRef::parse(source)?;
                    let mapping = compile_mapping(&field, mappings, capabilities)?;
                    normalized.insert(name.clone(), marker(FIELD, V::string(source)));
                    CustomBinding::Field(field, mapping)
                }
            } else {
                authored.closed(&[], &[FIELD, CONSTANT])?;
                let marker = authored.as_object()?;
                if let Some(source) = marker.get(FIELD) {
                    if marker.len() != 1 {
                        return Err(Error::invalid("recorded custom binding"));
                    }
                    let field = FieldRef::parse(source.as_str()?)?;
                    let mapping = compile_mapping(&field, mappings, capabilities)?;
                    CustomBinding::Field(field, mapping)
                } else if let Some(constant) = marker.get(CONSTANT) {
                    if marker.len() != 1 {
                        return Err(Error::invalid("recorded custom binding"));
                    }
                    charge_value(constant, budget)?;
                    CustomBinding::Constant(constant.clone())
                } else {
                    return Err(Error::invalid("recorded custom binding"));
                }
            };
            bindings.insert(name.clone(), binding);
        }
    }
    if bounds.is_some() {
        let V::Object(object) = value else {
            return Err(Error::invalid("custom predicate"));
        };
        if object.contains_key("bind") {
            object.insert("bind".into(), V::Object(normalized));
        }
    }
    Ok(CustomProgram {
        program: Program {
            init,
            lets,
            next,
            keep: keep.to_owned(),
        },
        bindings,
    })
}

fn marker(kind: &str, value: V) -> V {
    V::Object([(kind.to_owned(), value)].into_iter().collect())
}
