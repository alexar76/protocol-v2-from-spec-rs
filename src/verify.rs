//! Manifest (§7.3.2) and federation announce (§7.3.5), from the specification.
//! The reference hub sources were not consulted.
use crate::jsontext::{emit_spaced, J};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Fixed vector key from test-vectors/README.md. A key inside the document is a claim.
pub const PINNED_PUBLIC_KEY_B64: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

pub fn pinned_key() -> VerifyingKey {
    key_from_b64(PINNED_PUBLIC_KEY_B64).expect("pinned vector key")
}

pub fn key_from_b64(b64: &str) -> Result<VerifyingKey, String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| e.to_string())?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "public key is not 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| e.to_string())
}

fn sha256_hex(bytes: &str) -> String {
    let dig = Sha256::digest(bytes.as_bytes());
    hex_encode(&dig)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn sig_bytes(doc: &J) -> Result<Vec<u8>, String> {
    let sig = doc.get("signature").ok_or("signature missing")?;
    let algorithm = sig.get("algorithm").and_then(|v| v.as_str()).unwrap_or("");
    if algorithm != "ed25519" {
        return Err("algorithm is not ed25519".into());
    }
    let value = sig
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or("signature value missing")?;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| e.to_string())
}

fn verify(key: &VerifyingKey, canonical: &str, sig: &[u8]) -> bool {
    let Ok(signature) = Signature::from_slice(sig) else {
        return false;
    };
    key.verify(canonical.as_bytes(), &signature).is_ok()
}

/// Five-field manifest canonical. Absent `by_hub` hashes as `{}`.
pub fn manifest_canonical(doc: &J) -> Result<String, String> {
    let caps = match doc.get("capabilities_count") {
        Some(J::Num(n)) => n.clone(),
        None => "0".into(),
        _ => return Err("capabilities_count".into()),
    };
    let generated = match doc.get("generated_at") {
        Some(J::Str(s)) => s.clone(),
        None => String::new(),
        _ => return Err("generated_at".into()),
    };
    let proto = match doc.get("protocol_version") {
        Some(J::Str(s)) => s.clone(),
        None => "v1".into(),
        _ => return Err("protocol_version".into()),
    };
    let tools = doc.get("tools").cloned().unwrap_or(J::Arr(vec![]));
    let by_hub = doc.get("by_hub").cloned().unwrap_or(J::Obj(vec![]));
    Ok(format!(
        "capabilities_count:{caps}|generated_at:{generated}|protocol_version:{proto}|tools_hash:{}|by_hub_hash:{}",
        sha256_hex(&emit_spaced(&tools)),
        sha256_hex(&emit_spaced(&by_hub))
    ))
}

pub fn verify_manifest(doc: &J, key: &VerifyingKey) -> Result<bool, String> {
    let canonical = manifest_canonical(doc)?;
    let sig = sig_bytes(doc)?;
    Ok(verify(key, &canonical, &sig))
}

pub fn announce_canonical(doc: &J) -> Result<String, String> {
    let hub = doc
        .get("hub_url")
        .and_then(|v| v.as_str())
        .ok_or("hub_url")?;
    let well = doc
        .get("well_known_url")
        .and_then(|v| v.as_str())
        .ok_or("well_known_url")?;
    let caps = match doc.get("capabilities_count") {
        Some(J::Num(n)) => n.clone(),
        None => "0".into(),
        _ => return Err("capabilities_count".into()),
    };
    Ok(format!(
        "hub_url:{hub}|well_known_url:{well}|capabilities_count:{caps}"
    ))
}

pub fn verify_announce(doc: &J, key: &VerifyingKey) -> Result<bool, String> {
    let canonical = announce_canonical(doc)?;
    let sig = sig_bytes(doc)?;
    Ok(verify(key, &canonical, &sig))
}

/// Discovery document required by schemas/well-known.json. The document itself is unsigned.
pub fn well_known_required(doc: &J) -> Result<(), String> {
    for key in ["name", "protocol_versions", "manifest_url", "signer_public_key"] {
        if doc.get(key).is_none() {
            return Err(format!("missing {key}"));
        }
    }
    match doc.get("protocol_versions") {
        Some(J::Arr(items)) if !items.is_empty() => Ok(()),
        _ => Err("protocol_versions".into()),
    }
}

/// Body of `POST /ai-market/v2/channel/open` as the protocol README shows it.
/// Sending it transfers tokens into escrow (§6.1). This function does not send it.
pub fn channel_open_body(deposit_usd: &str) -> String {
    format!("{{\"deposit_usd\":{deposit_usd}}}")
}

/// Body of `POST /ai-market/v2/channel/close` (§6.1). The hub then submits `settleChannel`.
pub fn channel_close_body(channel_id: &str) -> String {
    format!("{{\"channel_id\":{}}}", crate::jsontext::emit_spaced(&crate::jsontext::J::Str(channel_id.to_string())))
}
