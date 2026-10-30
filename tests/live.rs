//! Read-only live discovery. Channel open is not called: §6.1 says it transfers
//! tokens into escrow.
use protocol_v2_from_spec_rs::{
    channel_close_body, channel_open_body, key_from_b64, parse, verify_manifest, well_known_required,
};

const HUB: &str = "https://modelmarket.dev";

#[test]
fn channel_open_body_matches_the_readme_shape() {
    assert_eq!(channel_open_body("3.0"), "{\"deposit_usd\":3.0}");
    assert_eq!(
        channel_close_body("ch_abc"),
        "{\"channel_id\":\"ch_abc\"}"
    );
}

#[test]
fn live_well_known_and_manifest() {
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .build();
    let well_url = format!("{HUB}/.well-known/ai-market.json");
    let well_body = agent
        .get(&well_url)
        .set("User-Agent", "AIMarketHub/2.0.0")
        .set("X-AIMarket-Crawler", "https://protocol-v2-from-spec-rs.invalid")
        .call()
        .expect("well-known")
        .into_string()
        .expect("well-known body");
    let well = parse(&well_body).expect("well-known json");
    well_known_required(&well).unwrap();

    let manifest_url = well
        .get("manifest_url")
        .and_then(|v| v.as_str())
        .expect("manifest_url")
        .to_string();
    let pin = well
        .get("signer_public_key")
        .and_then(|v| v.as_str())
        .expect("signer_public_key");
    let key = key_from_b64(pin).expect("signer key");

    let manifest_body = agent
        .get(&manifest_url)
        .set("User-Agent", "AIMarketHub/2.0.0")
        .call()
        .unwrap_or_else(|e| panic!("manifest {manifest_url}: {e}"))
        .into_string()
        .expect("manifest body");
    let manifest = parse(&manifest_body).expect("manifest json");
    let ok = verify_manifest(&manifest, &key).unwrap_or_else(|e| panic!("{e}: {manifest_body}"));
    assert!(ok, "live manifest signature did not verify against signer_public_key");
}
