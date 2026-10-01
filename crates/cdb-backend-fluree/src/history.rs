use crate::{journal::*, native::*, options::AuthorityOptions};
use cdb_core::{
    admission::*, id::*, record_codec, snapshot::*, storage_origin::RecordOrigin,
    CanonicalValue as V, Timestamp,
};
use std::collections::BTreeMap;

pub(crate) fn snapshot(o: &AuthorityOptions, p: NativePin) -> NativeResult<SnapshotRef> {
    Ok(SnapshotRef::new(
        o.backend.clone(),
        GraphPin::new(
            o.authority.clone(),
            o.graph.clone(),
            VersionId::new(p.t.to_string())?,
            ResourceId::new(p.cid)?,
        ),
    ))
}
pub(crate) fn pin(s: &SnapshotRef) -> NativeResult<NativePin> {
    let t = s.pin().revision().as_str().parse::<i64>()?;
    if t < 2 || t.to_string() != s.pin().revision().as_str() {
        return Err("invalid authority revision".into());
    }
    Ok(NativePin {
        t,
        cid: s.pin().receipt().as_str().into(),
    })
}
/// Bounded full ancestry audit. Journal is authoritative; physical images must agree.
pub(crate) async fn audit(
    n: &NativeStore,
    o: &AuthorityOptions,
    target: &NativePin,
) -> NativeResult<Vec<ChangeBatch>> {
    n.validate_pin(target).await?;
    if target.t < 2 || target.t as u64 > o.max_history_commits as u64 {
        return Err("history bound exceeded".into());
    }
    Ok(audit_from(n, o, target, None).await?.batches)
}
#[derive(Clone)]
pub(crate) struct Checkpoint {
    pub pin: NativePin,
    state: BTreeMap<String, ExportRecord>,
    controls: BTreeMap<(String, String), NativeRecord>,
    batches: Vec<ChangeBatch>,
    bytes: usize,
    work: usize,
    last: Option<Timestamp>,
    closed: Option<Timestamp>,
}
/// Predict exactly the next full-audit row work and decoded change bytes.
/// The checkpoint retains cumulative counters, including across incremental audits.
/// Image serialization matches the fixed native SPARQL projection.
pub(crate) fn prospective(
    o: &AuthorityOptions,
    pin: &NativePin,
    checkpoint: Option<&Checkpoint>,
    delete: &[NativeRecord],
    insert: &[NativeRecord],
) -> NativeResult<()> {
    let mut image = BTreeMap::new();
    let (work, mut bytes) = if pin.t == 1 {
        (0, 0)
    } else {
        let c = checkpoint
            .filter(|c| c.pin == *pin)
            .ok_or("missing prospective checkpoint")?;
        image = c.controls.clone();
        for r in c.state.values() {
            let r = encode(r, o.codec_limits)?;
            image.insert((r.kind.clone(), r.key.clone()), r);
        }
        (c.work, c.bytes)
    };
    for r in delete {
        if image.remove(&(r.kind.clone(), r.key.clone())).as_ref() != Some(r) {
            return Err("prospective deletion mismatch".into());
        }
    }
    for r in insert {
        image.insert((r.kind.clone(), r.key.clone()), r.clone());
        if r.kind == "journal" {
            let v = value(r)?;
            for change in v["changes"].as_array().ok_or("missing changes")? {
                bytes = bytes
                    .checked_add(change.as_str().ok_or("change string")?.len())
                    .ok_or_else(|| limit("history bytes exceeded"))?;
            }
        }
    }
    if work
        .checked_add(image.len())
        .is_none_or(|n| n > o.native_limits.max_records)
    {
        return Err(limit("history work exceeded"));
    }
    if bytes > o.native_limits.max_result_bytes {
        return Err(limit("history bytes exceeded"));
    }
    if crate::native::image_result_bytes(image.values())? > o.native_limits.max_result_bytes {
        return Err(limit("prospective native image bytes exceeded"));
    }
    Ok(())
}
fn limit(message: &str) -> Box<dyn std::error::Error + Send + Sync> {
    cdb_core::Error::new(cdb_core::ErrorKind::Limit, message).into()
}
pub(crate) async fn audit_from(
    n: &NativeStore,
    o: &AuthorityOptions,
    target: &NativePin,
    checkpoint: Option<Checkpoint>,
) -> NativeResult<Checkpoint> {
    n.validate_pin(target).await?;
    if target.t < 2 || target.t as u64 > o.max_history_commits as u64 {
        return Err("history bound exceeded".into());
    }
    let base = match checkpoint {
        Some(c) => c,
        None => {
            let p = n.pin_at(1).await?;
            if !n.read_records(&p, None).await?.is_empty() {
                return Err("unmanaged bootstrap".into());
            }
            n.audit_physical(&p, 0).await?;
            Checkpoint {
                pin: p,
                state: BTreeMap::new(),
                controls: BTreeMap::new(),
                batches: vec![],
                bytes: 0,
                work: 0,
                last: None,
                closed: None,
            }
        }
    };
    let Checkpoint {
        pin: mut previous,
        mut state,
        mut controls,
        mut batches,
        mut bytes,
        mut work,
        mut last,
        mut closed,
    } = base;
    for t in previous.t + 1..=target.t {
        let p = n.pin_at(t).await?;
        let rows = n.read_records(&p, None).await?;
        work = work
            .checked_add(rows.len())
            .ok_or("history work exceeded")?;
        if work > o.native_limits.max_records {
            return Err("history work exceeded".into());
        }
        n.audit_physical(&p, rows.len()).await?;
        let actual: BTreeMap<_, _> = rows
            .iter()
            .map(|r| ((r.kind.clone(), r.key.clone()), r.clone()))
            .collect();
        let j = actual
            .get(&("journal".into(), t.to_string()))
            .ok_or("missing journal gap")?;
        let v = value(j)?;
        if text(&v, "t")? != t.to_string()
            || text(&v, "predecessor_t")? != previous.t.to_string()
            || text(&v, "predecessor_cid")? != previous.cid
        {
            return Err("journal ancestry mismatch".into());
        }
        let op = text(&v, "operation")?;
        if (t == 2 && op != "init") || (t > 2 && op != "admit" && op != "capture") {
            return Err("unknown journal operation".into());
        }
        let wire = v["changes"].as_array().ok_or("missing changes")?;
        if wire.len() > o.max_changes.saturating_mul(2) {
            return Err("change bound exceeded".into());
        }
        if op != "admit" && !wire.is_empty() {
            return Err("control changes invalid".into());
        }
        let mut changes = Vec::new();
        for c in wire {
            let s = c.as_str().ok_or("change string missing")?;
            bytes = bytes.checked_add(s.len()).ok_or("history bytes exceeded")?;
            if bytes > o.native_limits.max_result_bytes {
                return Err("history bytes exceeded".into());
            }
            changes.push(record_codec::decode_change(s.as_bytes(), o.codec_limits)?);
        }
        let time = if op == "init" {
            None
        } else {
            Some(Timestamp::parse(text(&v, "time")?)?)
        };
        if op == "admit" {
            let time = time.ok_or("missing admission time")?;
            if last.into_iter().chain(closed).any(|b| time <= b) {
                return Err("admission clock regression".into());
            }
            validate_payload(&state, &changes, &v, t, time, o)?;
            last = Some(time);
        } else {
            for k in ["key", "payload", "digest"] {
                if !text(&v, k)?.is_empty() {
                    return Err("control admission fields".into());
                }
            }
            if v["claims"] != serde_json::json!([]) {
                return Err("control claims".into());
            }
            if op == "init" {
                if !text(&v, "time")?.is_empty() {
                    return Err("init clock".into());
                }
            } else {
                let cutoff = time.ok_or("capture time")?;
                closed = Some(closed.map_or(cutoff, |old| old.max(cutoff)));
            }
        }
        for c in &changes {
            apply(&mut state, c, o)?;
        }
        controls.insert(("journal".into(), t.to_string()), j.clone());
        if op == "admit" {
            if ContentHash::of_bytes(text(&v, "payload")?.as_bytes()).as_str()
                != text(&v, "digest")?
            {
                return Err("admission digest mismatch".into());
            }
            let mut receipt = j.clone();
            receipt.kind = "receipt".into();
            receipt.key = text(&v, "key")?.into();
            if controls
                .insert((receipt.kind.clone(), receipt.key.clone()), receipt)
                .is_some()
            {
                return Err("duplicate receipt".into());
            }
        }
        let owner = actual
            .get(&("control".into(), "owner".into()))
            .ok_or("missing owner")?;
        let ov = value(owner)?;
        for (k, expected) in [
            ("backend", o.backend.as_str()),
            ("authority", o.authority.as_str()),
            ("graph", o.graph.as_str()),
            ("ledger", o.ledger.as_str()),
        ] {
            if text(&ov, k)? != expected {
                return Err("foreign owner".into());
            }
        }
        if text(&ov, "t")? != t.to_string() {
            return Err("owner t mismatch".into());
        }
        if text(&ov, "last")? != last.map(|t| t.canonical()).unwrap_or_default()
            || text(&ov, "closed")? != closed.map(|t| t.canonical()).unwrap_or_default()
        {
            return Err("owner clock transition".into());
        }
        controls.insert(("control".into(), "owner".into()), owner.clone());
        let mut expected = controls.clone();
        for r in state.values() {
            let r = encode(r, o.codec_limits)?;
            expected.insert((r.kind.clone(), r.key.clone()), r);
        }
        if expected != actual {
            return Err("journal/physical image mismatch".into());
        }
        if t > 2 {
            batches.push(ChangeBatch::new(
                "ctxql-change/v1",
                snapshot(o, previous.clone())?,
                snapshot(o, p.clone())?,
                changes,
                o.codec_limits,
            )?);
        }
        previous = p;
    }
    if previous != *target {
        return Err("target mismatch".into());
    }
    Ok(Checkpoint {
        pin: previous,
        state,
        controls,
        batches,
        bytes,
        work,
        last,
        closed,
    })
}
fn apply(
    state: &mut BTreeMap<String, ExportRecord>,
    c: &RecordChange,
    o: &AuthorityOptions,
) -> NativeResult<()> {
    let (record, previous, remove) = match c {
        RecordChange::ClaimAdded(c) => (ExportRecord::Claim(c.clone()), None, false),
        RecordChange::LifecycleAdded {
            assertion,
            transaction_time,
        } => (
            ExportRecord::Lifecycle {
                assertion: assertion.clone(),
                transaction_time: *transaction_time,
            },
            None,
            false,
        ),
        RecordChange::ArtifactAdded(a) => (ExportRecord::Artifact(a.clone()), None, false),
        RecordChange::Resource(ResourceChange::Add(r)) => {
            (ExportRecord::Resource(r.clone()), None, false)
        }
        RecordChange::Resource(ResourceChange::ReplaceMutable { previous, record }) => (
            ExportRecord::Resource(record.clone()),
            Some(previous),
            false,
        ),
        RecordChange::Resource(ResourceChange::RetractMutable { id, kind, previous }) => {
            let r = state
                .get(&resource_key(id.as_str()))
                .ok_or("retraction gap")?
                .clone();
            if !matches!(&r,ExportRecord::Resource(r) if r.kind()==*kind) {
                return Err("retract kind mismatch".into());
            }
            (r, Some(previous), true)
        }
    };
    let key = record.identity_key();
    if let Some(hash) = previous {
        let Some(ExportRecord::Resource(old)) = state.get(&key) else {
            return Err("previous image missing".into());
        };
        if matches!(&record, ExportRecord::Resource(new) if new.kind() != old.kind())
            || !old.kind().mutable()
            || ContentHash::of_bytes(&old.projection().canonical_bytes(o.codec_limits)?) != *hash
        {
            return Err("previous hash mismatch".into());
        }
    } else if state.contains_key(&key) {
        return Err("immutable record conflict".into());
    }
    if remove {
        state.remove(&key);
    } else {
        state.insert(key, record);
    }
    Ok(())
}

fn validate_payload(
    state: &BTreeMap<String, ExportRecord>,
    changes: &[RecordChange],
    wire: &serde_json::Value,
    t: i64,
    time: Timestamp,
    o: &AuthorityOptions,
) -> NativeResult<()> {
    if !changes.len().is_multiple_of(2) {
        return Err("missing origins".into());
    }
    let (data, origins) = changes.split_at(changes.len() / 2);
    let mut claims = vec![];
    let mut lifecycle = vec![];
    let mut resources = vec![];
    let mut artifacts = vec![];
    for (c, origin) in data.iter().zip(origins) {
        let (r, removed) = match c {
            RecordChange::ClaimAdded(c) => {
                if c.transaction_time() != time {
                    return Err("claim clock".into());
                }
                claims.push(c.candidate().clone());
                (ExportRecord::Claim(c.clone()), false)
            }
            RecordChange::LifecycleAdded {
                assertion,
                transaction_time,
            } => {
                if *transaction_time != time {
                    return Err("lifecycle clock".into());
                }
                lifecycle.push(assertion.clone());
                (
                    ExportRecord::Lifecycle {
                        assertion: assertion.clone(),
                        transaction_time: *transaction_time,
                    },
                    false,
                )
            }
            RecordChange::ArtifactAdded(a) => {
                artifacts.push(a.clone());
                (ExportRecord::Artifact(a.clone()), false)
            }
            RecordChange::Resource(c) => {
                resources.push(c.clone());
                match c {
                    ResourceChange::Add(r) | ResourceChange::ReplaceMutable { record: r, .. } => {
                        (ExportRecord::Resource(r.clone()), false)
                    }
                    ResourceChange::RetractMutable { id, .. } => (
                        state
                            .get(&resource_key(id.as_str()))
                            .ok_or("origin previous missing")?
                            .clone(),
                        true,
                    ),
                }
            }
        };
        let expected = RecordChange::Resource(ResourceChange::Add(
            RecordOrigin::new(&r, t as u64, time, removed, o.codec_limits)?
                .resource(o.codec_limits)?,
        ));
        if *origin != expected {
            return Err("origin image mismatch".into());
        }
    }
    let payload = V::parse(text(wire, "payload")?.as_bytes(), o.codec_limits)?;
    let batch = AdmissionBatch::new(
        claims,
        lifecycle,
        resources,
        artifacts,
        payload.field("origin")?.clone(),
        o.codec_limits,
    )?;
    if batch.projection().canonical_bytes(o.codec_limits)? != text(wire, "payload")?.as_bytes() {
        return Err("payload normalized changes mismatch".into());
    }
    batch.validate_claim_references(
        &state
            .values()
            .filter_map(|r| r.claim().map(|c| c.id().clone()))
            .collect(),
    )?;
    let mut staged = state.clone();
    for c in data {
        apply(&mut staged, c, o)?;
    }
    for l in batch.lifecycle() {
        if let Some(e) = l.event() {
            if !matches!(staged.get(&resource_key(e.as_str())),Some(ExportRecord::Resource(r)) if r.kind()==ResourceKind::LifecycleEvent)
            {
                return Err("lifecycle event missing/wrong kind".into());
            }
        }
    }
    let ids: Vec<_> = batch
        .claims()
        .iter()
        .map(|c| c.id().as_str())
        .chain(batch.lifecycle().iter().map(|c| c.id().as_str()))
        .collect();
    if wire["claims"] != serde_json::json!(ids) {
        return Err("receipt claims mismatch".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prospective_change_bytes_include_checkpoint_total() -> NativeResult<()> {
        let mut o = AuthorityOptions::new(
            "unused".into(),
            "test:main".into(),
            BackendId::new("b")?,
            AuthorityId::new("a")?,
            GraphId::new("g")?,
        );
        o.native_limits.max_result_bytes = 8192;
        let p = NativePin {
            t: 2,
            cid: "previous".into(),
        };
        let mut c = Checkpoint {
            pin: p.clone(),
            state: BTreeMap::new(),
            controls: BTreeMap::new(),
            batches: vec![],
            bytes: 8189,
            work: 2,
            last: None,
            closed: None,
        };
        let j = control(
            "journal",
            "3",
            serde_json::json!({"schema":"ctxql-authority/v1","changes":["abc"]}),
        )?;
        prospective(&o, &p, Some(&c), &[], std::slice::from_ref(&j))?;
        c.bytes += 1;
        let e = prospective(&o, &p, Some(&c), &[], &[j]).unwrap_err();
        assert_eq!(
            e.downcast_ref::<cdb_core::Error>().unwrap().kind,
            cdb_core::ErrorKind::Limit
        );
        Ok(())
    }
    #[test]
    fn payload_and_origin_are_independently_bound() -> NativeResult<()> {
        let o = AuthorityOptions::new(
            "unused".into(),
            "test:main".into(),
            BackendId::new("b")?,
            AuthorityId::new("a")?,
            GraphId::new("g")?,
        );
        let r = DependencyRecord::new(
            "ctxql-resource/v1",
            ResourceId::new("r")?,
            ResourceKind::Label,
            vec![Fact::new(
                Iri::new("urn:p")?,
                FactTerm::Reference(ResourceId::new("v")?),
            )],
        )?;
        let batch = AdmissionBatch::new(
            vec![],
            vec![],
            vec![ResourceChange::Add(r.clone())],
            vec![],
            V::object([])?,
            o.codec_limits,
        )?;
        let time = Timestamp::from_millis(0)?;
        let origin = RecordOrigin::new(
            &ExportRecord::Resource(r.clone()),
            3,
            time,
            false,
            o.codec_limits,
        )?
        .resource(o.codec_limits)?;
        let mut changes = vec![
            RecordChange::Resource(ResourceChange::Add(r)),
            RecordChange::Resource(ResourceChange::Add(origin)),
        ];
        let mut wire = serde_json::json!({"payload":String::from_utf8(batch.projection().canonical_bytes(o.codec_limits)?)?,"claims":[]});
        validate_payload(&BTreeMap::new(), &changes, &wire, 3, time, &o)?;
        assert!(validate_payload(&BTreeMap::new(), &changes, &wire, 4, time, &o).is_err());
        wire["payload"] = serde_json::json!("{}");
        assert!(validate_payload(&BTreeMap::new(), &changes, &wire, 3, time, &o).is_err());
        changes.pop();
        assert!(validate_payload(&BTreeMap::new(), &changes, &wire, 3, time, &o).is_err());
        Ok(())
    }
}
