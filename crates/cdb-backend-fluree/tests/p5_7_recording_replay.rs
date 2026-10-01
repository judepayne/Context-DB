use std::path::Path;

/// Final v3 replay is exercised by the official two-scope load/reopen evidence
/// test, which owns the exact certified profiles and external cache authority.
/// This guard prevents the old regression from recreating an official-looking
/// synthetic certificate.
#[test]
#[ignore = "final replay requires exact external Relations and Agreements caches; run the official load/reopen evidence test"]
fn final_v3_recording_replay_requires_official_authority_caches() {
    let relations = std::env::var("CTXQL_P6_REFERENCE_CACHE")
        .unwrap_or_else(|_| "/tmp/ctxql-p6-reference-cache".into());
    let agreements = std::env::var("CTXQL_P5_7_AGREEMENTS_CACHE")
        .unwrap_or_else(|_| "/tmp/ctxql-p5-7-reference-cache".into());
    assert!(Path::new(&relations).is_absolute());
    assert!(Path::new(&agreements).is_absolute());
    assert!(
        Path::new(&relations).is_dir(),
        "Relations authority cache missing"
    );
    assert!(
        Path::new(&agreements).is_dir(),
        "Agreements authority cache missing"
    );
}
