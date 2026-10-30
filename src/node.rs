//! Directory node written from the protocol text (spec.md, schemas, test vectors).
//! It does not use the Python reference hub.
//!
//! A crawled peer stays untrusted until the operator admits it. Only admitted
//! peers are published in `peers` and searched. Everyone else is `observed_hubs`.
use crate::jsontext::{emit_spaced, parse, J};
use crate::safety::check_fetch_url;
use crate::verify::{self, key_from_b64};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const BODY_LIMIT: u64 = 1_000_000;
const PENDING_CAP: usize = 100;

#[derive(Clone, Debug)]
pub struct Peer {
    pub url: String,
    pub name: String,
    pub capabilities_count: u64,
    pub tools: J,
    pub admitted: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Directory {
    pub peers: BTreeMap<String, Peer>,
}

impl Directory {
    /// §2.4: an announcement about a peer we already know changes nothing.
    pub fn observe(&mut self, peer: Peer) -> Result<(), &'static str> {
        if self.peers.contains_key(&peer.url) {
            return Ok(());
        }
        let pending = self.peers.values().filter(|p| !p.admitted).count();
        if !peer.admitted && pending >= PENDING_CAP {
            return Err("pending cap");
        }
        self.peers.insert(peer.url.clone(), peer);
        Ok(())
    }

    pub fn admit(&mut self, url: &str) -> bool {
        match self.peers.get_mut(url) {
            Some(peer) => {
                peer.admitted = true;
                true
            }
            None => false,
        }
    }
}

pub fn well_known(
    name: &str,
    hub_url: &str,
    public_key_b64: &str,
    seeds: &[String],
    dir: &Directory,
) -> String {
    let peers: Vec<J> = dir.peers.values().filter(|p| p.admitted).map(peer_json).collect();
    let observed: Vec<J> = dir
        .peers
        .values()
        .filter(|p| !p.admitted)
        .map(|p| {
            J::Obj(vec![
                ("url".into(), J::Str(p.url.clone())),
                ("name".into(), J::Str(p.name.clone())),
                ("status".into(), J::Str("observed".into())),
            ])
        })
        .collect();
    emit_spaced(&J::Obj(vec![
        ("name".into(), J::Str(name.into())),
        (
            "protocol_versions".into(),
            J::Arr(vec![J::Str("v1".into()), J::Str("v2".into())]),
        ),
        ("hub_version".into(), J::Str("0.1.0".into())),
        ("manifest_url".into(), J::Str(format!("{hub_url}/ai-market/v2/manifest"))),
        ("capabilities_count".into(), J::Num(admitted_tools(dir).to_string())),
        ("signer_public_key".into(), J::Str(public_key_b64.into())),
        (
            "federation".into(),
            J::Obj(vec![
                ("crawl_interval_s".into(), J::Num("3600".into())),
                ("routing_fee_bps".into(), J::Num("0".into())),
                ("min_trust_score".into(), J::Num("0".into())),
                ("seed_list".into(), J::Arr(seeds.iter().cloned().map(J::Str).collect())),
            ]),
        ),
        ("peers".into(), J::Arr(peers)),
        ("observed_hubs".into(), J::Arr(observed)),
    ]))
}

fn peer_json(p: &Peer) -> J {
    J::Obj(vec![
        ("url".into(), J::Str(p.url.clone())),
        ("name".into(), J::Str(p.name.clone())),
        ("capabilities_count".into(), J::Num(p.capabilities_count.to_string())),
    ])
}

fn admitted_tools(dir: &Directory) -> usize {
    dir.peers
        .values()
        .filter(|p| p.admitted)
        .map(|p| match &p.tools {
            J::Arr(xs) => xs.len(),
            _ => 0,
        })
        .sum()
}

pub fn signed_manifest(dir: &Directory, key: &SigningKey) -> Result<String, String> {
    let mut tools = Vec::new();
    let mut by_hub = Vec::new();
    for peer in dir.peers.values().filter(|p| p.admitted) {
        if let J::Arr(xs) = &peer.tools {
            tools.extend(xs.clone());
        }
        by_hub.push((
            peer.url.clone(),
            J::Obj(vec![(
                "capabilities_count".into(),
                J::Num(peer.capabilities_count.to_string()),
            )]),
        ));
    }
    let doc = J::Obj(vec![
        ("protocol_version".into(), J::Str("v2".into())),
        ("generated_at".into(), J::Str(now_rfc3339())),
        ("capabilities_count".into(), J::Num(tools.len().to_string())),
        ("tools".into(), J::Arr(tools)),
        ("by_hub".into(), J::Obj(by_hub)),
    ]);
    attach_manifest_signature(doc, key)
}

fn attach_manifest_signature(doc: J, key: &SigningKey) -> Result<String, String> {
    let canonical = verify::manifest_canonical(&doc)?;
    let public = base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
    let sig = base64::engine::general_purpose::STANDARD.encode(key.sign(canonical.as_bytes()).to_bytes());
    let mut pairs = match doc {
        J::Obj(p) => p,
        _ => return Err("manifest".into()),
    };
    pairs.push((
        "signature".into(),
        J::Obj(vec![
            ("algorithm".into(), J::Str("ed25519".into())),
            ("public_key".into(), J::Str(public)),
            ("value".into(), J::Str(sig)),
        ]),
    ));
    Ok(emit_spaced(&J::Obj(pairs)))
}

pub fn signed_announce(hub_url: &str, capabilities_count: u64, key: &SigningKey) -> Result<String, String> {
    let doc = J::Obj(vec![
        ("hub_url".into(), J::Str(hub_url.into())),
        ("well_known_url".into(), J::Str(format!("{hub_url}/.well-known/ai-market.json"))),
        ("capabilities_count".into(), J::Num(capabilities_count.to_string())),
    ]);
    let canonical = verify::announce_canonical(&doc)?;
    let public = base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
    let sig = base64::engine::general_purpose::STANDARD.encode(key.sign(canonical.as_bytes()).to_bytes());
    let mut pairs = match doc {
        J::Obj(p) => p,
        _ => return Err("announce".into()),
    };
    pairs.push(("signer_public_key".into(), J::Str(public)));
    pairs.push((
        "signature".into(),
        J::Obj(vec![
            ("algorithm".into(), J::Str("ed25519".into())),
            ("value".into(), J::Str(sig)),
        ]),
    ));
    Ok(emit_spaced(&J::Obj(pairs)))
}

/// Inbound announce. The sender's key proves they signed the bytes. It does not admit them.
pub fn accept_announce(dir: &mut Directory, body: &str) -> Result<(), String> {
    let doc = parse(body)?;
    let claimed = doc
        .get("signer_public_key")
        .and_then(|v| v.as_str())
        .ok_or("signer_public_key")?;
    let key = key_from_b64(claimed)?;
    if !verify::verify_announce(&doc, &key)? {
        return Err("signature".into());
    }
    let hub = doc.get("hub_url").and_then(|v| v.as_str()).ok_or("hub_url")?;
    check_fetch_url(hub)?;
    let name = doc.get("hub_name").and_then(|v| v.as_str()).unwrap_or(hub);
    let caps = match doc.get("capabilities_count") {
        Some(J::Num(n)) => n.parse().unwrap_or(0),
        _ => 0,
    };
    dir.observe(Peer {
        url: hub.to_string(),
        name: name.to_string(),
        capabilities_count: caps,
        tools: J::Arr(vec![]),
        admitted: false,
    })
    .map_err(|e| e.to_string())
}

pub fn search(dir: &Directory, intent: &str) -> String {
    let needle = intent.to_lowercase();
    let mut matches = Vec::new();
    for peer in dir.peers.values().filter(|p| p.admitted) {
        let J::Arr(tools) = &peer.tools else { continue };
        for tool in tools {
            let blob = format!(
                "{} {}",
                tool.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                tool.get("description").and_then(|v| v.as_str()).unwrap_or("")
            )
            .to_lowercase();
            if needle.is_empty() || blob.contains(&needle) {
                matches.push(J::Obj(vec![
                    ("product_id".into(), tool.get("product_id").cloned().unwrap_or(J::Str(String::new()))),
                    (
                        "capability_id".into(),
                        tool.get("capability_id").cloned().unwrap_or(J::Str(String::new())),
                    ),
                    ("source_hub".into(), J::Str(peer.url.clone())),
                    ("source_hub_name".into(), J::Str(peer.name.clone())),
                    (
                        "price_per_call_usd".into(),
                        tool.get("price_per_call_usd").cloned().unwrap_or(J::Num("0".into())),
                    ),
                ]));
            }
        }
    }
    let total = dir.peers.values().filter(|p| p.admitted).count();
    emit_spaced(&J::Obj(vec![
        ("query".into(), J::Str(intent.into())),
        ("matches".into(), J::Arr(matches)),
        ("total_hubs_searched".into(), J::Num(total.to_string())),
        ("protocol_version".into(), J::Str("v2".into())),
    ]))
}

/// Fetch one operator seed. A new peer is admitted only if its origin is in `admitted`.
pub fn crawl_one(dir: &mut Directory, seed: &str, admitted: &BTreeSet<String>) -> Result<(), String> {
    check_fetch_url(seed)?;
    let well = parse(&get_bounded(seed)?)?;
    verify::well_known_required(&well)?;
    let manifest_url = well.get("manifest_url").and_then(|v| v.as_str()).ok_or("manifest_url")?;
    check_fetch_url(manifest_url)?;
    let pin = well.get("signer_public_key").and_then(|v| v.as_str()).ok_or("signer")?;
    let key = key_from_b64(pin)?;
    let manifest = parse(&get_bounded(manifest_url)?)?;
    if !verify::verify_manifest(&manifest, &key)? {
        return Err("manifest signature".into());
    }
    let url = origin_of(seed)?;
    let name = well.get("name").and_then(|v| v.as_str()).unwrap_or(&url).to_string();
    let caps = match manifest.get("capabilities_count") {
        Some(J::Num(n)) => n.parse().unwrap_or(0),
        _ => 0,
    };
    let tools = manifest.get("tools").cloned().unwrap_or(J::Arr(vec![]));
    if dir.peers.contains_key(&url) {
        if admitted.contains(&url) {
            if let Some(peer) = dir.peers.get_mut(&url) {
                peer.name = name;
                peer.capabilities_count = caps;
                peer.tools = tools;
                peer.admitted = true;
            }
        }
        return Ok(());
    }
    dir.observe(Peer {
        url: url.clone(),
        name,
        capabilities_count: caps,
        tools,
        admitted: admitted.contains(&url),
    })
    .map_err(|e| e.to_string())
}

fn origin_of(raw: &str) -> Result<String, String> {
    let url = url::Url::parse(raw).map_err(|e| e.to_string())?;
    let host = url.host_str().ok_or("host")?;
    Ok(format!("{}://{host}", url.scheme()))
}

fn get_bounded(url: &str) -> Result<String, String> {
    let resp = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(10))
        .build()
        .get(url)
        .set("User-Agent", "AIMarketHub/2.0.0")
        .call()
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(BODY_LIMIT + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() as u64 > BODY_LIMIT {
        return Err("body too large".into());
    }
    String::from_utf8(buf).map_err(|e| e.to_string())
}

fn now_rfc3339() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
