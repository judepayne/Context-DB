use cdb_core::id::*;
#[test]
fn lexical_ids_and_iris() {
    assert!(ClaimId::new("opaque claim 🙂").is_ok());
    for s in [
        "https://EXAMPLE.org/%4a/é",
        "urn:example:abc",
        "ctxql:artifact/name",
    ] {
        assert_eq!(Iri::new(s).unwrap().as_str(), s);
    }
    for s in [
        "relative",
        "http:example.org",
        "https:///example.org",
        "https://x/%",
        "https://x/%gg",
        "https://x/a b",
        "https://x/\\a",
        "https://x/{a}",
    ] {
        assert!(Iri::new(s).is_err(), "{s}");
    }
    assert!(Iri::http("urn:valid").is_err());
    assert!(ClaimId::new("").is_err());
    assert!(ClaimId::new("a\nb").is_err());
}
#[test]
fn hash_spelling() {
    let h = ContentHash::of_bytes(b"abc");
    assert_eq!(
        h.as_str(),
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(ContentHash::parse(h.as_str().to_uppercase()).is_err());
    assert!(ContentHash::parse("sha256:example").is_err());
}
