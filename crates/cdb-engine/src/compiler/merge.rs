use cdb_core::{CanonicalValue as V, Error, Result};
use std::collections::BTreeSet;

pub(super) fn structural(v: &V, profile: bool) -> Result<()> {
    v.closed(
        &[],
        if profile {
            &[
                "name", "profile", "@context", "about", "bounds", "walk", "filter", "return",
            ]
        } else {
            &[
                "profile", "@context", "about", "bounds", "walk", "filter", "return",
            ]
        },
    )?;
    if let Some(n) = v.as_object()?.get("name") {
        n.as_str()?;
    }
    if let Some(c) = v.as_object()?.get("@context") {
        c.as_object()?;
    }
    if let Some(b) = v.as_object()?.get("bounds") {
        b.as_object()?;
    }
    if let Some(r) = v.as_object()?.get("return") {
        r.closed(&[], &["claims", "paths", "evidence", "explain"])?;
        for b in r.as_object()?.values() {
            b.as_bool()?;
        }
    }
    for phase in ["walk", "filter"] {
        if let Some(p) = v.as_object()?.get(phase) {
            p.closed(
                &[],
                if phase == "walk" {
                    &["direction", "predicates", "drop_predicates"]
                } else {
                    &["predicates", "drop_predicates"]
                },
            )?;
            if let Some(d) = p.as_object()?.get("direction") {
                d.as_str()?;
            }
            if let Some(d) = p.as_object()?.get("drop_predicates") {
                for n in d.as_array()? {
                    n.as_str()?;
                }
            }
            let mut names = BTreeSet::new();
            if let Some(predicates) = p.as_object()?.get("predicates") {
                for predicate in predicates.as_array()? {
                    match predicate {
                        V::Array(a) => triple(a)?,
                        V::Object(o) => {
                            if let Some(n) = o.get("name") {
                                let n = n.as_str()?;
                                cdb_core::id::ResourceId::new(n)?;
                                if !names.insert(n) {
                                    return Err(Error::invalid(
                                        "duplicate or empty predicate name",
                                    ));
                                }
                            }
                            if let Some(w) = o.get("where") {
                                predicate.closed(&["name", "where"], &[])?;
                                triple(w.as_array()?)?;
                            } else {
                                predicate
                                    .closed(&["keep"], &["name", "init", "bind", "let", "next"])?;
                                predicate.field("keep")?.as_str()?;
                                for key in ["init", "bind", "let", "next"] {
                                    if let Some(x) = o.get(key) {
                                        x.as_object()?;
                                    }
                                }
                            }
                        }
                        _ => return Err(Error::invalid("predicate structure")),
                    }
                }
            }
        }
    }
    Ok(())
}
fn triple(a: &[V]) -> Result<()> {
    if a.len() != 3 {
        return Err(Error::invalid("predicate triple"));
    }
    a[0].as_str()?;
    a[1].as_str()?;
    Ok(())
}
fn name(v: &V) -> Option<&str> {
    v.as_object().ok()?.get("name")?.as_str().ok()
}
pub(super) fn merge(base: &mut V, overlay: &V) {
    if let (V::Object(b), V::Object(o)) = (&mut *base, overlay) {
        for (k, v) in o {
            match b.get_mut(k) {
                Some(old) => merge(old, v),
                None => {
                    b.insert(k.clone(), v.clone());
                }
            }
        }
    } else {
        *base = overlay.clone();
    }
}
pub(super) fn merge_source(base: &mut V, overlay: &V) -> Result<()> {
    let mut ordinary = overlay.as_object()?.clone();
    for phase in ["walk", "filter"] {
        if let Some(p) = ordinary.remove(phase) {
            let mut phase_overlay = p.as_object()?.clone();
            let predicates = phase_overlay.remove("predicates");
            let drops = phase_overlay.remove("drop_predicates");
            let b = base
                .as_object()?
                .get(phase)
                .cloned()
                .ok_or_else(|| Error::invalid("phase defaults"))?;
            let mut b = b.as_object()?.clone();
            let mut inherited = b
                .get("predicates")
                .ok_or_else(|| Error::invalid("predicate defaults"))?
                .as_array()?
                .to_vec();
            if let Some(d) = drops {
                let drops = d
                    .as_array()?
                    .iter()
                    .map(V::as_str)
                    .collect::<Result<BTreeSet<_>>>()?;
                inherited.retain(|v| !name(v).is_some_and(|n| drops.contains(n)));
            }
            if let Some(p) = predicates {
                let p = p.as_array()?;
                if p.is_empty() {
                    inherited.clear();
                }
                let mut positions: std::collections::BTreeMap<String, usize> = inherited
                    .iter()
                    .enumerate()
                    .filter_map(|(i, v)| name(v).map(|n| (n.to_owned(), i)))
                    .collect();
                for v in p {
                    if let Some(index) = name(v).and_then(|n| positions.get(n)).copied() {
                        inherited[index] = v.clone();
                    } else {
                        if let Some(n) = name(v) {
                            positions.insert(n.to_owned(), inherited.len());
                        }
                        inherited.push(v.clone());
                    }
                }
            }
            b.insert("predicates".into(), V::Array(inherited));
            let mut b = V::Object(b);
            merge(&mut b, &V::Object(phase_overlay));
            if let V::Object(base) = base {
                base.insert(phase.into(), b);
            }
        }
    }
    merge(base, &V::Object(ordinary));
    Ok(())
}
