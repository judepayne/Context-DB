use cdb_core::{CanonicalValue as V, Error, Result};
use std::collections::BTreeSet;

pub(super) fn validate(v: &V, profile: bool) -> Result<()> {
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
    if let Some(p) = v.as_object()?.get("profile") {
        crate::artifacts::ArtifactName::new(p.as_str()?, usize::MAX)?;
    }
    if let Some(n) = v.as_object()?.get("name") {
        crate::artifacts::ArtifactName::new(n.as_str()?, usize::MAX)?;
    }
    if let Some(c) = v.as_object()?.get("@context") {
        for value in c.as_object()?.values() {
            value.as_str()?;
        }
    }
    // Profile ABOUT is ignored by the compiler (with a notice), preserving the
    // historical rule that ignored profile content cannot block compilation.
    if let Some(a) = v.as_object()?.get("about").filter(|_| !profile) {
        for block in a.as_array()? {
            block.closed(&["from"], &["to", "match"])?;
            for key in ["from", "to"] {
                if let Some(a) = block.as_object()?.get(key) {
                    for anchor in a.as_array()? {
                        anchor.as_str()?;
                    }
                }
            }
            if let Some(m) = block.as_object()?.get("match") {
                m.as_str()?;
            }
        }
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
                                        for value in x.as_object()?.values() {
                                            if key != "init" {
                                                value.as_str()?;
                                            }
                                        }
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
