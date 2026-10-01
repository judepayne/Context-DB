mod common;
use cdb_core::{ErrorKind, ExactNumber as N};
use common::*;
fn n(s: &str) -> N {
    N::parse(s).unwrap()
}
#[test]
fn selected_numeric_fixture() {
    let f = json(include_str!(
        "../../../fixtures/conformance/canonical/numeric-defaults.json"
    ));
    for v in f.field("normalization").unwrap().as_array().unwrap() {
        assert_eq!(
            n(v.field("input").unwrap().as_str().unwrap()).token(),
            v.field("token").unwrap().as_str().unwrap()
        );
    }
    for v in f.field("comparisons").unwrap().as_array().unwrap() {
        let a = n(v.field("left").unwrap().as_str().unwrap());
        let b = n(v.field("right").unwrap().as_str().unwrap());
        assert_eq!(
            format!("{:?}", a.checked_cmp(&b).unwrap()).to_lowercase(),
            v.field("ordering").unwrap().as_str().unwrap()
        );
    }
    for v in f.field("arithmetic").unwrap().as_array().unwrap() {
        let a = n(v.field("left").unwrap().as_str().unwrap());
        let b = n(v.field("right").unwrap().as_str().unwrap());
        let r = match v.field("op").unwrap().as_str().unwrap() {
            "+" => a.checked_add(&b),
            "*" => a.checked_mul(&b),
            "/" => a.checked_div(&b),
            _ => unreachable!(),
        };
        if let Ok(t) = v.field("token") {
            assert_eq!(r.unwrap().token(), t.as_str().unwrap());
        } else {
            assert!(r.is_err());
        }
    }
    for v in f.field("admission").unwrap().as_array().unwrap() {
        let input = if let Ok(i) = v.field("input") {
            i.as_str().unwrap().to_owned()
        } else {
            let r = v.field("input_recipe").unwrap();
            r.field("repeat")
                .unwrap()
                .as_str()
                .unwrap()
                .repeat(r.field("count").unwrap().u64().unwrap() as usize)
        };
        assert_eq!(
            N::parse(&input).is_ok(),
            v.field("outcome").unwrap().as_str().unwrap() == "allowed"
        );
    }
}
#[test]
fn cancellation_and_exact_intermediates() {
    let a = n(&"9".repeat(128));
    assert_eq!(a.checked_add(&n("1")).unwrap(), n("1e128"));
    assert_eq!(n("1e128").checked_sub(&a).unwrap(), n("1"));
    assert_eq!(n("1e1024").checked_sub(&n("1e1024")).unwrap(), n("0"));
    assert_eq!(n("1e1024").checked_mul(&n("1e-1024")).unwrap(), n("1"));
    assert_eq!(n("1").checked_div(&n("1267650600228229401496703205376")).unwrap().token(),"0.0000000000000000000000000000007888609052210118054117285652827862296732064351090230047702789306640625");
}
#[test]
fn ieee_exact_not_shortest_string() {
    assert_eq!(
        N::from_binary64(0x3fb999999999999a).unwrap().token(),
        "0.1000000000000000055511151231257827021181583404541015625"
    );
    assert_ne!(N::from_binary64(0x3fb999999999999a).unwrap(), n("0.1"));
    assert_eq!(N::from_binary32(0x3f000000).unwrap(), n("0.5"));
    assert!(N::from_binary64(1).is_err());
    assert!(N::from_binary64(0x7ff0000000000000).is_err());
    assert_eq!(N::from_binary64(1u64 << 63).unwrap(), n("0"));
}
#[test]
fn invalid_lexemes_and_zero() {
    for s in [
        "", "+1", "01", "1.", ".1", "--1", "1e", "1e+", "NaN", " 1", "1 ",
    ] {
        assert!(N::parse(s).is_err(), "{s}");
    }
    assert_eq!(n("0e999999999999999999999999999999999999"), n("0"));
    assert_eq!(
        N::parse(&format!("0e{}", "0".repeat(8192)))
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
    assert!(N::parse("1e-999999999999999999999999").is_err());
}
