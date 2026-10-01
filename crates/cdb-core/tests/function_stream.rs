use cdb_core::{
    artifact::FunctionManifest, function_stream::FunctionRootStream, id::*,
    projection::FunctionRootProjection, CanonicalValue as V, Limits,
};
fn manifest() -> FunctionManifest {
    FunctionManifest::new(
        ResourceId::new("fn:\"\\雪").unwrap(),
        VersionId::new("v\"\\雪").unwrap(),
        V::Null,
        Limits::default(),
    )
    .unwrap()
}
#[test]
fn vector_oracle_empty_single_many_and_escaping() {
    let m = manifest();
    for n in [0, 1, 2, 37] {
        let hashes = (0..n)
            .map(|i| ContentHash::of_bytes(format!("call{i}").as_bytes()))
            .collect::<Vec<_>>();
        for output in [false, true] {
            let mut stream = FunctionRootStream::new(output, &m, Limits::default(), n).unwrap();
            for hash in &hashes {
                stream.push(hash).unwrap();
            }
            assert_eq!(stream.count(), n);
            assert_eq!(
                stream.finish().unwrap(),
                FunctionRootProjection::new(output, &m, &hashes)
                    .unwrap()
                    .canonical()
                    .hash(Limits::default())
                    .unwrap()
            );
        }
    }
}
#[test]
fn hundred_thousand_constant_space_matches_vector() {
    let m = manifest();
    let hash = ContentHash::of_bytes(b"same");
    let mut stream = FunctionRootStream::new(false, &m, Limits::default(), 100_000).unwrap();
    let size = std::mem::size_of_val(&stream);
    for _ in 0..100_000 {
        stream.push(&hash).unwrap();
    }
    assert_eq!(size, std::mem::size_of_val(&stream));
    assert_eq!(stream.count(), 100_000);
    assert!(stream.push(&hash).is_err());
    let large = Limits::new(32_000_000, 64, 1_000_000, 100_000_000, 32_000_000).unwrap();
    let oracle = FunctionRootProjection::new(false, &m, &vec![hash; 100_000])
        .unwrap()
        .canonical()
        .hash(large)
        .unwrap();
    assert_eq!(stream.finish().unwrap(), oracle);
}
#[test]
fn limits_are_injected_and_failed_push_does_not_change_root() {
    let m = manifest();
    let zero = Limits::new(0, 0, 0, 0, 0).unwrap();
    assert!(FunctionRootStream::new(false, &m, zero, 0).is_err());
    let mut stream = FunctionRootStream::new(false, &m, Limits::default(), 0).unwrap();
    assert!(stream.push(&ContentHash::of_bytes(b"x")).is_err());
    assert_eq!(stream.count(), 0);
    assert_eq!(
        stream.finish().unwrap(),
        FunctionRootProjection::new(false, &m, &[])
            .unwrap()
            .canonical()
            .hash(Limits::default())
            .unwrap()
    );
}
