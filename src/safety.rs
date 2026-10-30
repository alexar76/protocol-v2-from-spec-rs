//! §7.4 — refuse to fetch a stranger's URL that points into our own network.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use url::Url;

pub fn ip_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => ipv4_blocked(v),
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return ipv4_blocked(v4);
            }
            ipv6_blocked(v)
        }
    }
}

fn ipv4_blocked(v: Ipv4Addr) -> bool {
    let o = v.octets();
    let cgnat = o[0] == 100 && (o[1] & 0xc0) == 0x40;
    v.is_loopback()
        || v.is_private()
        || v.is_link_local()
        || v.is_broadcast()
        || v.is_documentation()
        || v.is_unspecified()
        || v.is_multicast()
        || cgnat
}

fn ipv6_blocked(v: Ipv6Addr) -> bool {
    // IPv4-compatible form ::a.b.c.d (obsolete, still named in §7.4).
    let s = v.segments();
    let v4_compatible = s[0..6].iter().all(|x| *x == 0) && s[6] != 0;
    v.is_loopback()
        || v.is_unspecified()
        || v.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
        || (s[0] & 0xffc0) == 0xfe80 // link-local
        || v4_compatible
}

/// Operator-supplied seeds are still checked. A pasted private URL must not be fetched.
pub fn check_fetch_url(raw: &str) -> Result<Url, String> {
    if raw.chars().any(|c| c.is_control()) {
        return Err("control character in url".into());
    }
    let url = Url::parse(raw).map_err(|e| e.to_string())?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err("scheme".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("userinfo".into());
    }
    let host = url.host_str().ok_or("host")?;
    let port = url.port_or_known_default().unwrap_or(80);
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?;
    let mut any = false;
    for addr in addrs {
        any = true;
        if ip_blocked(addr.ip()) {
            return Err(format!("blocked address {}", addr.ip()));
        }
    }
    if !any {
        return Err("no addresses".into());
    }
    Ok(url)
}
