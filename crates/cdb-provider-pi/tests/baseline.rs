use sha2::{Digest, Sha256};
#[test]
fn hmem_baseline_is_byte_exact() {
    let bytes = include_bytes!("../../../assets/pi/prompts/recorder-extraction-hmem-baseline.md");
    assert_eq!(
        format!("{:x}", Sha256::digest(bytes)),
        "cb395103b4821d13e607adb1fa43ec4f730768e1e9ff9a7d73958b07a1f96ade"
    );
}
