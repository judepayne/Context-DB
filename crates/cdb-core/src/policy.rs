//! Pure static-v1 evaluation only. Class sets below are trusted current-authority inputs, not credentials.
use crate::id::Iri;
use crate::{CanonicalValue as V, Error, Limits, Result};
use std::collections::BTreeSet;
const F: &str = "https://ns.flur.ee/db#";
#[derive(Clone, Debug, Eq, PartialEq)]
enum Target {
    Default,
    Subject(BTreeSet<Iri>),
    Property(BTreeSet<Iri>),
    Class(BTreeSet<Iri>),
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Rule {
    id: Iri,
    classes: BTreeSet<Iri>,
    allow: bool,
    required: bool,
    target: Target,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySet {
    rules: Vec<Rule>,
}
fn set(v: &V) -> Result<BTreeSet<Iri>> {
    let values = match v {
        V::String(_) => std::slice::from_ref(v),
        V::Array(a) => a,
        _ => return Err(Error::invalid("policy IRI set")),
    };
    if values.is_empty() {
        return Err(Error::invalid("empty policy set"));
    }
    values.iter().map(|v| Iri::http(v.as_str()?)).collect()
}
impl PolicySet {
    pub fn parse(bytes: &[u8], limits: Limits) -> Result<Self> {
        let limits = Limits::new(
            limits.input_bytes(),
            limits.depth().min(32),
            limits.values(),
            limits.work(),
            limits.output_bytes(),
        )?;
        Self::from_value(&V::parse(bytes, limits)?)
    }
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(&["contract", "guard", "policies"], &[])?;
        if v.field("contract")?.as_str()? != "ctxql-static-policy/v1"
            || v.field("guard")?.as_str()? != "ctxql-guard/v1"
        {
            return Err(Error::invalid("policy contract/guard"));
        }
        let mut rules = vec![];
        let mut ids = BTreeSet::new();
        for p in v.field("policies")?.as_array()? {
            p.closed(
                &[
                    "@id",
                    "@type",
                    "https://ns.flur.ee/db#action",
                    "https://ns.flur.ee/db#allow",
                ],
                &[
                    "https://ns.flur.ee/db#required",
                    "https://ns.flur.ee/db#onSubject",
                    "https://ns.flur.ee/db#onProperty",
                    "https://ns.flur.ee/db#onClass",
                ],
            )?;
            let id = Iri::http(p.field("@id")?.as_str()?)?;
            if !ids.insert(id.clone()) {
                return Err(Error::invalid("duplicate policy ID"));
            }
            let mut classes = set(p.field("@type")?)?;
            if !classes.remove(&Iri::http(format!("{F}AccessPolicy"))?) || classes.is_empty() {
                return Err(Error::invalid("policy types"));
            }
            let action = set(p.field(&format!("{F}action"))?)?;
            if action != BTreeSet::from([Iri::http(format!("{F}view"))?]) {
                return Err(Error::invalid("only view action supported"));
            }
            let allow = p.field(&format!("{F}allow"))?.as_bool()?;
            let required = p
                .as_object()?
                .get(&format!("{F}required"))
                .map(V::as_bool)
                .transpose()?
                .unwrap_or(false);
            let mut target = Target::Default;
            let mut count = 0;
            for kind in ["onSubject", "onProperty", "onClass"] {
                if let Some(v) = p.as_object()?.get(&format!("{F}{kind}")) {
                    count += 1;
                    let s = set(v)?;
                    target = match kind {
                        "onSubject" => Target::Subject(s),
                        "onProperty" => Target::Property(s),
                        _ => Target::Class(s),
                    };
                }
            }
            if count > 1 {
                return Err(Error::invalid("mixed policy target categories"));
            }
            rules.push(Rule {
                id,
                classes,
                allow,
                required,
                target,
            });
        }
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(Self { rules })
    }
    /// Caller must provide enabled membership and direct resource classes from one current context.
    /// Missing resource/disabled principal is denied; an existing untyped resource uses an empty set.
    pub fn allows(
        &self,
        enabled: bool,
        principal_classes: &BTreeSet<Iri>,
        resource: &Iri,
        property: &Iri,
        current_classes: Option<&BTreeSet<Iri>>,
    ) -> bool {
        self.allows_resource(
            enabled,
            principal_classes,
            resource.as_str(),
            property,
            current_classes,
        )
    }
    /// Domain resource IDs may be opaque. Target IRIs still match their exact
    /// lexical spelling; no invented IRI or normalization is used for an ID.
    pub fn allows_resource(
        &self,
        enabled: bool,
        principal_classes: &BTreeSet<Iri>,
        resource: &str,
        property: &Iri,
        current_classes: Option<&BTreeSet<Iri>>,
    ) -> bool {
        let Some(classes) = current_classes else {
            return false;
        };
        if !enabled {
            return false;
        }
        let applicable = |r: &&Rule| {
            !r.classes.is_disjoint(principal_classes)
                && match &r.target {
                    Target::Default => true,
                    Target::Subject(s) => s.iter().any(|iri| iri.as_str() == resource),
                    Target::Property(s) => s.contains(property),
                    Target::Class(s) => !s.is_disjoint(classes),
                }
        };
        let required = self.rules.iter().filter(applicable).any(|r| r.required);
        let mut any = false;
        for rule in self
            .rules
            .iter()
            .filter(applicable)
            .filter(|r| !required || r.required)
        {
            any = true;
            if !rule.allow {
                return false;
            }
        }
        any
    }
    /// Normalized authoritative representation; callers still provide trusted current state.
    pub fn projection(&self) -> V {
        use crate::value::obj;
        let policies = self
            .rules
            .iter()
            .map(|r| {
                let mut classes = r.classes.clone();
                classes.insert(Iri::http(format!("{F}AccessPolicy")).expect("constant IRI"));
                let mut fields = std::collections::BTreeMap::from([
                    ("@id".into(), V::string(r.id.as_str())),
                    (
                        "@type".into(),
                        V::Array(classes.iter().map(|c| V::string(c.as_str())).collect()),
                    ),
                    (format!("{F}action"), V::string(format!("{F}view"))),
                    (format!("{F}allow"), V::Bool(r.allow)),
                    (format!("{F}required"), V::Bool(r.required)),
                ]);
                let target = match &r.target {
                    Target::Default => None,
                    Target::Subject(s) => Some(("onSubject", s)),
                    Target::Property(s) => Some(("onProperty", s)),
                    Target::Class(s) => Some(("onClass", s)),
                };
                if let Some((name, values)) = target {
                    fields.insert(
                        format!("{F}{name}"),
                        V::Array(values.iter().map(|v| V::string(v.as_str())).collect()),
                    );
                }
                V::Object(fields)
            })
            .collect();
        obj([
            ("contract", V::string("ctxql-static-policy/v1")),
            ("guard", V::string("ctxql-guard/v1")),
            ("policies", V::Array(policies)),
        ])
    }
    pub fn len(&self) -> usize {
        self.rules.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}
