//! Operator process. Not the Python hub.
//!
//!   federator keygen --out operator.key
//!   federator serve --key operator.key --hub-url https://operator.example \
//!       --listen 127.0.0.1:8090 \
//!       --seed https://modelmarket.dev/.well-known/ai-market.json \
//!       --admit https://modelmarket.dev
use protocol_v2_from_spec_rs::node::{self, Directory};
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Response, Server, StatusCode};

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("keygen") => keygen(&args.collect::<Vec<_>>()),
        Some("serve") => serve(&args.collect::<Vec<_>>()),
        _ => {
            eprintln!("usage: federator keygen --out operator.key");
            eprintln!("       federator serve --key operator.key --hub-url URL --listen ADDR --seed URL [--admit ORIGIN]");
            std::process::exit(2);
        }
    }
}

fn keygen(args: &[String]) {
    let out = flag(args, "--out").unwrap_or_else(|| "operator.key".into());
    let key = SigningKey::generate(&mut OsRng);
    fs::write(&out, hex_encode(&key.to_bytes())).expect("write key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&out, fs::Permissions::from_mode(0o600));
    }
    let public = base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
    println!("wrote {out}");
    println!("public {public}");
    println!("this key is the operator's. Hand the file to the next operator with the process, not a copy of the Python hub.");
}

fn serve(args: &[String]) {
    let key_path = flag(args, "--key").expect("--key");
    let hub_url = flag(args, "--hub-url").expect("--hub-url").trim_end_matches('/').to_string();
    let listen = flag(args, "--listen").unwrap_or_else(|| "127.0.0.1:8090".into());
    let name = flag(args, "--name").unwrap_or_else(|| "federator".into());
    let seeds = flags(args, "--seed");
    let admitted: BTreeSet<String> = flags(args, "--admit").into_iter().collect();
    let key = load_key(Path::new(&key_path));
    let public = base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
    let dir = Arc::new(Mutex::new(Directory::default()));
    {
        let mut guard = dir.lock().expect("directory");
        for seed in &seeds {
            if let Err(err) = node::crawl_one(&mut guard, seed, &admitted) {
                eprintln!("seed {seed}: {err}");
            }
        }
    }
    let server = Server::http(&listen).unwrap_or_else(|e| panic!("listen {listen}: {e}"));
    eprintln!("federator {hub_url} on {listen}");
    for mut req in server.incoming_requests() {
        let path = req.url().split('?').next().unwrap_or("/");
        let query = req.url().split_once('?').map(|(_, q)| q).unwrap_or("");
        let guard = dir.lock().expect("directory");
        let (status, body) = match (req.method().as_str(), path) {
            ("GET", "/.well-known/ai-market.json") => {
                (200, node::well_known(&name, &hub_url, &public, &seeds, &guard))
            }
            ("GET", "/ai-market/v2/manifest") => match node::signed_manifest(&guard, &key) {
                Ok(body) => (200, body),
                Err(err) => (500, err),
            },
            ("GET", "/ai-market/v2/search") => (200, node::search(&guard, &query_param(query, "intent"))),
            ("POST", "/ai-market/v2/federation/announce") => {
                drop(guard);
                let mut raw = String::new();
                let _ = req.as_reader().take(1_000_001).read_to_string(&mut raw);
                let mut guard = dir.lock().expect("directory");
                match node::accept_announce(&mut guard, &raw) {
                    Ok(()) => (200, "{\"acknowledged\":true,\"peer_added\":false}".into()),
                    Err(err) if err == "pending cap" => (429, err),
                    Err(err) => (400, err),
                }
            }
            _ => (404, "not found".into()),
        };
        let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
        let _ = req.respond(Response::from_string(body).with_status_code(StatusCode(status)).with_header(header));
    }
}

fn load_key(path: &Path) -> SigningKey {
    let hex = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let bytes = hex_decode(hex.trim()).unwrap_or_else(|e| panic!("key: {e}"));
    let bytes: [u8; 32] = bytes.try_into().unwrap_or_else(|_| panic!("key must be 32 bytes"));
    SigningKey::from_bytes(&bytes)
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn flags(args: &[String], name: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .filter(|(_, a)| *a == name)
        .filter_map(|(i, _)| args.get(i + 1).cloned())
        .collect()
}

fn query_param(query: &str, name: &str) -> String {
    query
        .split('&')
        .find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == name).then(|| urlencoding_min(v))
        })
        .unwrap_or_default()
}

fn urlencoding_min(raw: &str) -> String {
    let mut out = String::new();
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16) {
                    out.push(v as char);
                    i += 3;
                } else {
                    out.push('%');
                    i += 1;
                }
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
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

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[allow(dead_code)]
fn _keep_write() {
    let _ = std::io::stdout().write_all(b"");
}
