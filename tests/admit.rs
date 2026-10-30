use ed25519_dalek::SigningKey;
use protocol_v2_from_spec_rs::node::{self, Directory, Peer};
use protocol_v2_from_spec_rs::{parse, verify_announce, verify_manifest, J};
use rand_core::OsRng;

fn sample(url: &str, admitted: bool) -> Peer {
    Peer {
        url: url.into(),
        name: "Other".into(),
        capabilities_count: 1,
        tools: J::Arr(vec![J::Obj(vec![
            ("name".into(), J::Str("translate.multi".into())),
            ("description".into(), J::Str("Translate text".into())),
            ("capability_id".into(), J::Str("translate.multi@v2".into())),
            ("product_id".into(), J::Str("prod-001".into())),
            ("price_per_call_usd".into(), J::Num("0.4".into())),
        ])]),
        admitted,
    }
}

#[test]
fn pending_peer_is_not_published_as_a_peer() {
    let mut dir = Directory::default();
    dir.observe(sample("https://stranger.example", false)).unwrap();
    let doc = parse(&node::well_known(
        "op",
        "https://op.example",
        "abc",
        &["https://modelmarket.dev/.well-known/ai-market.json".into()],
        &dir,
    ))
    .unwrap();
    match doc.get("peers") {
        Some(J::Arr(xs)) => assert!(xs.is_empty()),
        other => panic!("{other:?}"),
    }
    match doc.get("observed_hubs") {
        Some(J::Arr(xs)) => assert_eq!(xs.len(), 1),
        other => panic!("{other:?}"),
    }
    let found = parse(&node::search(&dir, "translate")).unwrap();
    match found.get("matches") {
        Some(J::Arr(xs)) => assert!(xs.is_empty(), "untrusted tools must not be searchable"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn admitted_peer_is_searchable_and_signed() {
    let mut dir = Directory::default();
    dir.observe(sample("https://peer.example", true)).unwrap();
    let found = parse(&node::search(&dir, "translate")).unwrap();
    match found.get("matches") {
        Some(J::Arr(xs)) => assert_eq!(xs.len(), 1),
        other => panic!("{other:?}"),
    }
    let key = SigningKey::generate(&mut OsRng);
    let manifest = parse(&node::signed_manifest(&dir, &key).unwrap()).unwrap();
    assert!(verify_manifest(&manifest, &key.verifying_key()).unwrap());
}

#[test]
fn own_announce_verifies_and_does_not_admit() {
    // Admission checks the address. A literal keeps this unit test independent
    // of DNS; accept_announce never connects to the advertised server.
    let hub = "https://93.184.216.34";
    let key = SigningKey::generate(&mut OsRng);
    let body = node::signed_announce(hub, 0, &key).unwrap();
    let mut dir = Directory::default();
    node::accept_announce(&mut dir, &body).unwrap();
    let peer = dir.peers.get(hub).unwrap();
    assert!(!peer.admitted);
    assert!(verify_announce(&parse(&body).unwrap(), &key.verifying_key()).unwrap());
    let again = node::signed_announce(hub, 9, &key).unwrap();
    node::accept_announce(&mut dir, &again).unwrap();
    assert_eq!(dir.peers.get(hub).unwrap().capabilities_count, 0);
}
