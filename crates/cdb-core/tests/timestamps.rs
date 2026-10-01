use cdb_core::Timestamp as T;
#[test]
fn utc_exact_milliseconds() {
    assert_eq!(T::parse("1969-12-31T23:59:59.999Z").unwrap().millis(), -1);
    assert_eq!(
        T::parse("2026-04-01T01:30:00.120000000000+01:30")
            .unwrap()
            .canonical(),
        "2026-04-01T00:00:00.120Z"
    );
    assert_eq!(
        T::parse("0001-01-01T00:00:00Z").unwrap().canonical(),
        "0001-01-01T00:00:00.000Z"
    );
}
#[test]
fn reject_precision_dates_leaps_offsets_and_overflow() {
    for s in [
        "2026-02-30T00:00:00Z",
        "2016-12-31T23:59:60Z",
        "2026-01-01T00:00:00.0001Z",
        "2026-01-01T00:00:00.000000000001Z",
        "2026-01-01T00:00:00+24:00",
        "0001-01-01T00:00:00+01:00",
        "9999-12-31T23:59:59.999-01:00",
    ] {
        assert!(T::parse(s).is_err(), "{s}");
    }
    assert!(T::parse("9999-12-31T23:59:59.999Z")
        .unwrap()
        .checked_add_millis(1)
        .is_err());
    assert!(T::from_millis(i64::MAX).is_err());
}
