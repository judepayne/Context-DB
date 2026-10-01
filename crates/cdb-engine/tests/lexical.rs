use cdb_core::{id::ResourceId, ErrorKind, Limits};
use cdb_engine::lexical::{score, Config, RESOLVER, UNICODE_VERSION};
fn check(anchor: &str, labels: &[&str], expected: Option<u64>) {
    assert_eq!(
        score(
            anchor,
            &ResourceId::new("https://example.test/bank-risk").unwrap(),
            &labels.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
            Config::new(RESOLVER, UNICODE_VERSION, 1).unwrap(),
            Limits::default()
        )
        .unwrap(),
        expected
    );
}
#[test]
fn exact_bonus_distinct_tokens_and_no_url_partial_match() {
    check("bank risk", &["RISK BANK", "Bank Risk"], Some(5));
    check("bank bank risk", &["bank"], Some(1));
    check("bank risk", &["risk / bank"], Some(2));
    check("bank", &[], None);
    check("https://example.test/bank-risk", &[], Some(11));
}
#[test]
fn unicode_scalar_lowercase_and_no_normalization_or_stemming() {
    check("İ", &["i"], Some(1)); // lowercasing yields i + combining dot, not full equality
    check("CAFÉ", &["café"], Some(3));
    check("é", &["e\u{301}"], None);
    check("banks", &["bank"], None);
    check("雨", &["雨 森"], Some(1));
}
#[test]
fn empty_tokens_full_label_whitespace_and_best_label() {
    check("!!!", &["???"], None);
    check("!!!", &["!!!"], Some(1));
    check("", &[""], Some(1));
    check(" bank ", &["bank"], Some(1));
    check(
        "bank risk",
        &["other", "risk", "BANK RISK", "bank"],
        Some(5),
    );
}
#[test]
fn explicit_identity_threshold_and_rejecting_budgets() {
    assert_eq!(
        Config::new(RESOLVER, (0, 0, 0), 1).unwrap_err().kind,
        ErrorKind::Unsupported
    );
    assert!(Config::new(RESOLVER, UNICODE_VERSION, 0).is_err());
    let config = Config::new(RESOLVER, UNICODE_VERSION, 2).unwrap();
    let id = ResourceId::new("id").unwrap();
    assert_eq!(
        score(
            "bank risk",
            &id,
            &["bank".into()],
            config,
            Limits::default()
        )
        .unwrap(),
        None
    );
    assert_eq!(
        score(
            "bank risk",
            &id,
            &["BANK RISK".into()],
            config,
            Limits::default()
        )
        .unwrap(),
        Some(5)
    );
    assert_eq!(
        score("id", &id, &[], config, Limits::new(0, 0, 0, 0, 0).unwrap())
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
    assert_eq!(
        score(
            "id",
            &id,
            &["large".repeat(100)],
            config,
            Limits::new(64, 4, 64, 10000, 64).unwrap()
        )
        .unwrap_err()
        .kind,
        ErrorKind::Limit
    );
}
