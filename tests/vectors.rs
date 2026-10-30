use protocol_v2_from_spec_rs::{
    emit_spaced, parse, pinned_key, verify_announce, verify_manifest, J,
};
use std::fs;

fn load(rel: &str) -> J {
    let path = format!("../aimarket-protocol/test-vectors/{rel}");
    parse(&fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))).unwrap()
}

#[test]
fn empty_object_digest_matches_the_vector_readme() {
    // by_hub_hash of an absent by_hub, published next to the vectors.
    assert_eq!(emit_spaced(&J::Obj(vec![])), "{}");
}

#[test]
fn manifest_and_announce_vectors() {
    let key = pinned_key();
    let cases = [
        ("manifest-signed.json", true, true),
        ("negative/manifest-tampered-price.json", true, false),
        ("negative/manifest-tampered-by-hub.json", true, false),
        ("negative/manifest-legacy-3field-canonical.json", true, false),
        ("federation-announce-signed.json", false, true),
        ("negative/announce-tampered-hub-url.json", false, false),
    ];
    for (file, is_manifest, accept) in cases {
        let doc = load(file);
        let ok = if is_manifest {
            verify_manifest(&doc, &key).unwrap()
        } else {
            verify_announce(&doc, &key).unwrap()
        };
        assert_eq!(ok, accept, "{file}");
    }
}
