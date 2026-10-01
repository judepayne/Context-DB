//! Versioned control wire. Core values are embedded only as canonical UTF-8 strings.
use crate::native::{NativeRecord, NativeResult};
use cdb_core::{
    admission::{ExportRecord, RecordChange},
    id::ContentHash,
    record_codec, Limits,
};
use serde_json::{json, Value};
pub(crate) fn control(kind: &str, key: &str, value: Value) -> NativeResult<NativeRecord> {
    let payload = serde_json::to_string(&value)?;
    Ok(NativeRecord {
        kind: kind.into(),
        key: key.into(),
        hash: ContentHash::of_bytes(payload.as_bytes()).as_str().into(),
        payload,
    })
}
pub(crate) fn value(r: &NativeRecord) -> NativeResult<Value> {
    if ContentHash::of_bytes(r.payload.as_bytes()).as_str() != r.hash {
        return Err("control hash mismatch".into());
    }
    let v: Value = serde_json::from_str(&r.payload)?;
    if text(&v, "schema")? != "ctxql-authority/v1" {
        return Err("unknown authority schema".into());
    }
    Ok(v)
}
pub(crate) fn text<'a>(v: &'a Value, k: &str) -> NativeResult<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string {k}").into())
}
pub(crate) fn encode(r: &ExportRecord, limits: Limits) -> NativeResult<NativeRecord> {
    let payload = String::from_utf8(record_codec::encode_record(r, limits)?)?;
    Ok(NativeRecord {
        kind: "record".into(),
        key: r.identity_key(),
        hash: ContentHash::of_bytes(payload.as_bytes()).as_str().into(),
        payload,
    })
}
pub(crate) fn decode(r: &NativeRecord, limits: Limits) -> NativeResult<ExportRecord> {
    let result = record_codec::decode_record(r.payload.as_bytes(), limits)?;
    if encode(&result, limits)? != *r {
        return Err("record mirrors/hash mismatch".into());
    }
    Ok(result)
}
pub(crate) fn changes(changes: &[RecordChange], limits: Limits) -> NativeResult<Value> {
    Ok(json!(changes
        .iter()
        .map(|c| Ok(String::from_utf8(record_codec::encode_change(c, limits)?)?))
        .collect::<NativeResult<Vec<_>>>()?))
}
