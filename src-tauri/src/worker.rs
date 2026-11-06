//! The Cloudflare Worker carrier: a VLESS-over-WebSocket proxy the user deploys
//! to their own Cloudflare account, reached through a pinned Xray child process.
//!
//! The same design as the Android client (WhiteAestherMobile 1.15.1): the
//! script in `assets/worker.js` is uploaded unchanged, Xray opens a SOCKS
//! listener on loopback, and the carrier is reported up only after a verified
//! TLS handshake has crossed it. Everything after that listener -- mihomo, the
//! system proxy, full tunnel -- is the path every other carrier already uses.
//!
//! What is stored and what is not: deployment records, including each
//! deployment's connection identity, live in the app data directory, as the
//! Android client keeps them in app-private storage. The Cloudflare API token
//! is never stored; every management command takes it as an argument and drops
//! it when the command returns.

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};

use crate::carrier::{Carrier, CarrierKind};
use crate::core_supervisor::CoreSupervisor;

/// The script deployed to Cloudflare, byte for byte the Android 1.15.1 asset.
pub(crate) const WORKER_SCRIPT: &str = include_str!("../assets/worker.js");

#[cfg(windows)]
const XRAY_FILENAME: &str = "xray.exe";
#[cfg(not(windows))]
const XRAY_FILENAME: &str = "xray";
const MANIFEST_FILENAME: &str = "xray-manifest.json";

/// Hosts the connection test asks for. Neither is behind Cloudflare: a Worker
/// cannot `connect()` to Cloudflare addresses directly, so a Cloudflare-hosted
/// target would test the NAT64 fallback rather than the Worker.
pub(crate) const PROBE_TARGETS: [&str; 2] = ["www.google.com", "www.wikipedia.org"];

/// How long a connect may take before it is reported as failed.
const START_TIMEOUT: Duration = Duration::from_secs(90);

pub const TLS_PORTS: [u16; 6] = [443, 8443, 2053, 2083, 2087, 2096];
pub const FINGERPRINTS: [&str; 10] =
    ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"];
const CLOUDFLARE_DNS: [&str; 6] = [
    "1.1.1.1",
    "1.0.0.1",
    "cloudflare-dns.com",
    "one.one.one.one",
    "security.cloudflare-dns.com",
    "family.cloudflare-dns.com",
];

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum WorkerMode {
    #[default]
    Normal,
    Fragment,
    Browser,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct WorkerFragment {
    pub packets: String,
    pub lengths: String,
    pub delays: String,
    pub max_split: String,
}

impl Default for WorkerFragment {
    fn default() -> Self {
        Self { packets: "tlshello".into(), lengths: "100-200".into(), delays: "1".into(), max_split: String::new() }
    }
}

impl WorkerFragment {
    fn validate(&self) -> Result<(), String> {
        if self.packets != "tlshello" {
            let shape = self.packets.split_once('-').is_some_and(|(a, b)| {
                [a, b].iter().all(|p| (1..=3).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_digit()) && !p.starts_with('0'))
            });
            if !shape {
                return Err("Invalid fragment packets".into());
            }
            ranges(&self.packets, 1, 255)?;
        }
        ranges(&self.lengths, 1, 65535)?;
        ranges(&self.delays, 0, 1000)?;
        if !self.max_split.trim().is_empty() && ranges(&self.max_split, 1, 65535)?.len() != 1 {
            return Err("Use one maximum-split range".into());
        }
        Ok(())
    }

    fn mask(&self) -> Value {
        let mut settings = json!({
            "packets": self.packets,
            "lengths": ranges(&self.lengths, 1, 65535).unwrap_or_default(),
            "delays": ranges(&self.delays, 0, 1000).unwrap_or_default(),
        });
        if !self.max_split.trim().is_empty() {
            settings["maxSplit"] = json!(ranges(&self.max_split, 1, 65535).unwrap_or_default()[0]);
        }
        json!({ "type": "fragment", "settings": settings })
    }
}

fn ranges(value: &str, minimum: u32, maximum: u32) -> Result<Vec<String>, String> {
    let values: Vec<String> = value.split(',').map(|v| v.trim().to_string()).collect();
    if !(1..=16).contains(&values.len()) {
        return Err("Use between 1 and 16 fragment ranges".into());
    }
    for entry in &values {
        let parts: Vec<&str> = entry.split('-').collect();
        let numeric = |p: &str| (1..=5).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_digit());
        if parts.len() > 2 || !parts.iter().all(|p| numeric(p)) {
            return Err("Use fragment ranges such as 100-200".into());
        }
        let first: u32 = parts[0].parse().unwrap_or(u32::MAX);
        let last: u32 = parts[parts.len() - 1].parse().unwrap_or(u32::MAX);
        if !(minimum..=maximum).contains(&first) || !(first..=maximum).contains(&last) {
            return Err("Fragment range is out of bounds".into());
        }
    }
    Ok(values)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct WorkerOptions {
    pub mode: WorkerMode,
    pub clean_addresses: Vec<String>,
    pub ports: Vec<u16>,
    pub fingerprint: String,
    pub remote_dns: String,
    pub ech: bool,
    pub ech_dns: String,
    pub custom_cdn: bool,
    pub cdn_addresses: Vec<String>,
    pub cdn_host: String,
    pub cdn_sni: String,
    pub fragments: Vec<WorkerFragment>,
    pub upstream_proxy: String,
    pub proxy_ips: Vec<String>,
    pub fallback_url: String,
    pub tcp_fast_open: bool,
    pub probe_interval: u32,
}

impl Default for WorkerOptions {
    fn default() -> Self {
        Self {
            mode: WorkerMode::Normal,
            clean_addresses: vec!["104.17.148.22".into(), "104.17.147.22".into()],
            ports: vec![443],
            fingerprint: "chrome".into(),
            remote_dns: "https://8.8.8.8/dns-query".into(),
            ech: false,
            ech_dns: "https://8.8.8.8/dns-query".into(),
            custom_cdn: false,
            cdn_addresses: Vec::new(),
            cdn_host: String::new(),
            cdn_sni: String::new(),
            fragments: vec![WorkerFragment::default()],
            upstream_proxy: String::new(),
            proxy_ips: Vec::new(),
            fallback_url: String::new(),
            tcp_fast_open: false,
            probe_interval: 60,
        }
    }
}

impl WorkerOptions {
    pub fn validate(&self) -> Result<(), String> {
        if self.clean_addresses.len() > 32 || self.cdn_addresses.len() > 32 || self.proxy_ips.len() > 16 {
            return Err("Too many Worker addresses".into());
        }
        for address in self.clean_addresses.iter().chain(&self.cdn_addresses) {
            if !valid_host(address) {
                return Err(format!("Invalid Worker address: {address}"));
            }
        }
        let mut unique = self.ports.clone();
        unique.sort_unstable();
        unique.dedup();
        if self.ports.is_empty() || unique.len() != self.ports.len() || !self.ports.iter().all(|p| TLS_PORTS.contains(p)) {
            return Err(format!(
                "Select Cloudflare TLS ports: {}",
                TLS_PORTS.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")
            ));
        }
        if !FINGERPRINTS.contains(&self.fingerprint.as_str()) {
            return Err("Unsupported TLS fingerprint".into());
        }
        let (Some(remote), Some(_)) = (dns_host(&self.remote_dns), dns_host(&self.ech_dns)) else {
            return Err("Use a public HTTPS or TCP DNS address".into());
        };
        if CLOUDFLARE_DNS.contains(&remote.to_ascii_lowercase().as_str()) {
            return Err("Workers cannot reach Cloudflare DNS; use another provider".into());
        }
        if self.custom_cdn && (self.cdn_addresses.is_empty() || !valid_host(&self.cdn_host) || !valid_host(&self.cdn_sni)) {
            return Err("Custom CDN requires addresses, Host and SNI".into());
        }
        if !(1..=8).contains(&self.fragments.len()) {
            return Err("Use between 1 and 8 fragment entries".into());
        }
        for fragment in &self.fragments {
            fragment.validate()?;
        }
        if !self.upstream_proxy.is_empty() && relay_parts(&self.upstream_proxy).is_none_or(|(_, port)| port.is_none()) {
            return Err("Use upstream host:port".into());
        }
        if self.proxy_ips.iter().any(|ip| ip.trim().is_empty() || !valid_relay(ip)) {
            return Err("Invalid proxy IP address".into());
        }
        if !self.fallback_url.is_empty() && !valid_fallback(&self.fallback_url) {
            return Err("Use an HTTPS fallback website".into());
        }
        if !(10..=300).contains(&self.probe_interval) {
            return Err("Probe interval must be between 10 and 300 seconds".into());
        }
        Ok(())
    }
}

/// A bare host: DNS name, IPv4, or IPv6 (bracketed or not), with nothing else.
pub fn valid_host(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let bare = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')).unwrap_or(value);
    if bare.contains(':') {
        return bare.parse::<Ipv6Addr>().is_ok();
    }
    if bare.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    // URI host syntax as java.net.URI accepts it for a server-based authority.
    let labels: Vec<&str> = bare.trim_end_matches('.').split('.').collect();
    let label = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    labels.iter().all(label) && labels.last().is_some_and(|l| l.bytes().next().is_some_and(|c| c.is_ascii_alphabetic()) || labels.len() == 1)
}

/// `host[:port]`, with IPv6 bracketed when a port follows.
fn relay_parts(value: &str) -> Option<(String, Option<u16>)> {
    if value.is_empty() || value.len() > 253 || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    if value.contains(['/', '?', '#', '@']) {
        return None;
    }
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        match after.strip_prefix(':') {
            Some(port) => (format!("[{inside}]"), Some(port)),
            None if after.is_empty() => (format!("[{inside}]"), None),
            None => return None,
        }
    } else {
        match value.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host.to_string(), Some(port)),
            Some(_) => return None,
            None => (value.to_string(), None),
        }
    };
    if !valid_host(&host) {
        return None;
    }
    let port = match port {
        Some(text) => {
            let number: u16 = text.parse().ok().filter(|p| *p != 0)?;
            Some(number)
        }
        None => None,
    };
    Some((host, port))
}

pub fn valid_relay(value: &str) -> bool {
    value.is_empty() || relay_parts(value).is_some()
}

/// `https://host[:port][/path]` or `tcp://...`; returns the host.
fn dns_host(value: &str) -> Option<String> {
    let rest = value.strip_prefix("https://").or_else(|| value.strip_prefix("tcp://"))?;
    if value.contains('#') {
        return None;
    }
    let authority = rest.split(['/', '?']).next()?;
    if authority.contains('@') {
        return None;
    }
    let (host, _) = relay_parts(authority)?;
    Some(host.trim_start_matches('[').trim_end_matches(']').to_string())
}

fn valid_fallback(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else { return false };
    if value.contains('#') || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    !authority.contains('@') && relay_parts(authority).is_some_and(|(host, _)| valid_host(&host))
}

// ---------------------------------------------------------------------------
// Deployments
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerDeployment {
    pub account_id: String,
    pub name: String,
    pub pages: bool,
    pub uuid: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub relay: String,
    #[serde(default)]
    pub created: bool,
    #[serde(default)]
    pub ready: bool,
    #[serde(default)]
    pub options: WorkerOptions,
    #[serde(default)]
    pub custom_domain: String,
    #[serde(default = "one")]
    pub version: u32,
    #[serde(default)]
    pub domain_pending: bool,
    #[serde(default)]
    pub dns_zone: String,
    #[serde(default)]
    pub dns_record: String,
}

fn one() -> u32 {
    1
}

pub(crate) fn hex32(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|c| c.is_ascii_hexdigit())
}

pub(crate) fn valid_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(g, n)| g.len() == n && g.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
}

pub(crate) fn random_uuid() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the OS random source is available");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

/// A name like "quiet-river-3f9a2c" that looks like any hobby project and says nothing about the app,
/// so one leaked hostname cannot be used to find and report every other user's deployment.
pub(crate) fn neutral_name() -> String {
    const FIRST: [&str; 16] = [
        "quiet", "amber", "silver", "misty", "bold", "calm", "rapid", "sunny", "lucky", "gentle", "brave", "crisp", "fuzzy", "lively", "royal", "sharp",
    ];
    const SECOND: [&str; 16] = [
        "river", "forest", "meadow", "harbor", "canyon", "breeze", "falcon", "maple", "pebble", "summit", "lagoon", "willow", "comet", "garden", "island", "valley",
    ];
    let mut bytes = [0u8; 5];
    getrandom::fill(&mut bytes).expect("the OS random source is available");
    let tail: String = bytes[2..].iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{tail}", FIRST[(bytes[0] & 15) as usize], SECOND[(bytes[1] & 15) as usize])
}

impl WorkerDeployment {
    pub fn new(account_id: &str, pages: bool, relay: &str) -> Result<Self, String> {
        let deployment = Self {
            account_id: account_id.to_string(),
            name: neutral_name(),
            pages,
            uuid: random_uuid(),
            host: String::new(),
            relay: relay.trim().to_string(),
            created: false,
            ready: false,
            options: WorkerOptions::default(),
            custom_domain: String::new(),
            version: 1,
            domain_pending: false,
            dns_zone: String::new(),
            dns_record: String::new(),
        };
        deployment.validate()?;
        Ok(deployment)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !hex32(&self.account_id) {
            return Err("Invalid Cloudflare account".into());
        }
        // Older releases named every deployment "whiteaesther-<hex>"; those stay valid.
        let name = &self.name;
        if !(1..=53).contains(&name.len())
            || name.starts_with('-')
            || name.ends_with('-')
            || !name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return Err("Invalid deployment name".into());
        }
        if !valid_uuid(&self.uuid) {
            return Err("Invalid connection identifier".into());
        }
        if !valid_relay(&self.relay) {
            return Err("Invalid relay address".into());
        }
        if !self.custom_domain.is_empty() && (!valid_host(&self.custom_domain) || self.custom_domain.contains(':')) {
            return Err("Invalid custom domain".into());
        }
        self.options.validate()?;
        if ![&self.dns_zone, &self.dns_record].iter().all(|v| v.is_empty() || hex32(v)) {
            return Err("Invalid saved DNS record".into());
        }
        Ok(())
    }

    pub fn key(&self) -> String {
        format!("{}/{}/{}", self.account_id, if self.pages { "pages" } else { "workers" }, self.name)
    }

    pub fn connection_host(&self) -> &str {
        if self.domain_pending || self.custom_domain.is_empty() {
            &self.host
        } else {
            &self.custom_domain
        }
    }

    pub fn has_public_host(&self) -> bool {
        let labels: Vec<&str> = self.host.split('.').collect();
        self.host.len() <= 253
            && labels.len() >= 2
            && labels.iter().all(|l| {
                !l.is_empty() && l.len() <= 63 && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') && !l.starts_with('-') && !l.ends_with('-')
            })
            && labels.last().is_some_and(|l| l.bytes().any(|c| c.is_ascii_alphabetic()))
    }

    /// The settings the script reads, base64 JSON in its `ENV` binding.
    pub fn environment(&self) -> String {
        let mut pips: Vec<String> = Vec::new();
        for ip in self.options.proxy_ips.iter().chain(std::iter::once(&self.relay)).filter(|v| !v.is_empty()) {
            if !pips.contains(ip) {
                pips.push(ip.clone());
            }
        }
        let document = json!({ "v": 1, "id": self.uuid, "pips": pips, "fb": self.options.fallback_url });
        base64(document.to_string().as_bytes())
    }

    /// Hides this deployment's identity and settings in a line meant for a log.
    pub fn redact(&self, line: &str) -> String {
        line.replace(&self.uuid, "[identity]").replace(&self.environment(), "[settings]")
    }
}

pub(crate) fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Xray config
// ---------------------------------------------------------------------------

/// BPB's Worker variants, rendered for the pinned Xray core.
pub fn render_config(deployment: &WorkerDeployment, socks_port: u16) -> Result<String, String> {
    let options = &deployment.options;
    options.validate()?;
    if socks_port == 0 {
        return Err("Invalid SOCKS port".into());
    }
    let domain = deployment.connection_host().to_string();
    if !deployment.ready || !valid_host(&domain) {
        return Err("Select a deployed Worker first".into());
    }
    let browser = options.mode == WorkerMode::Browser;
    let fragment = options.mode == WorkerMode::Fragment;

    let mut candidates: Vec<(String, u16)> = Vec::new();
    if browser {
        candidates.push((domain.clone(), 443));
    } else {
        let mut addresses = vec![domain.clone()];
        addresses.extend(options.clean_addresses.iter().cloned());
        if options.custom_cdn && !fragment {
            addresses.extend(options.cdn_addresses.iter().cloned());
        }
        let mut unique: Vec<String> = Vec::new();
        for address in addresses {
            if !unique.contains(&address) {
                unique.push(address);
            }
        }
        for port in &options.ports {
            for address in &unique {
                candidates.push((address.clone(), *port));
            }
        }
        if !fragment && !options.upstream_proxy.is_empty() {
            if let Some((host, Some(port))) = relay_parts(&options.upstream_proxy) {
                candidates.push((host.trim_start_matches('[').trim_end_matches(']').to_string(), port));
            }
        }
    }
    let mut endpoints: Vec<(String, u16)> = Vec::new();
    for candidate in candidates {
        if !endpoints.contains(&candidate) {
            endpoints.push(candidate);
        }
    }

    let mut outbounds: Vec<Value> = Vec::new();
    for (index, (address, port)) in endpoints.iter().enumerate() {
        let custom = !browser && !fragment && options.custom_cdn && options.cdn_addresses.contains(address);
        let host = if custom { options.cdn_host.clone() } else { domain.clone() };
        let mut tls = json!({ "serverName": if custom { options.cdn_sni.clone() } else { domain.clone() }, "alpn": ["http/1.1"] });
        if !browser {
            tls["fingerprint"] = json!(options.fingerprint);
            if options.ech && !fragment {
                tls["echConfigList"] = json!(format!("cloudflare-ech.com+{}", options.ech_dns));
                tls["echSockopt"] = json!({ "dialerProxy": "worker-direct" });
            }
        }
        let mut stream = json!({
            "network": "ws",
            "security": "tls",
            "tlsSettings": tls,
            "wsSettings": { "host": host, "path": "/?ed=2560" },
            "sockopt": { "tcpFastOpen": options.tcp_fast_open, "domainStrategy": "UseIP" },
        });
        if fragment {
            stream["finalmask"] = json!({ "tcp": options.fragments.iter().map(WorkerFragment::mask).collect::<Vec<_>>() });
        }
        outbounds.push(json!({
            "tag": format!("worker-node-{}", index + 1),
            "protocol": "vless",
            "settings": {
                "address": address.trim_start_matches('[').trim_end_matches(']'),
                "port": port,
                "id": deployment.uuid,
                "encryption": "none",
            },
            "streamSettings": stream,
        }));
    }
    outbounds.push(json!({ "tag": "worker-direct", "protocol": "freedom" }));
    outbounds.push(json!({ "tag": "worker-block", "protocol": "blackhole" }));

    let mut route = json!({ "type": "field", "inboundTag": ["worker-in"] });
    if browser {
        route["outboundTag"] = json!("worker-node-1");
    } else {
        route["balancerTag"] = json!("worker-best");
    }
    let mut routing = json!({
        "domainStrategy": "AsIs",
        "rules": [{ "type": "field", "network": "udp", "outboundTag": "worker-block" }, route],
    });
    if !browser {
        routing["balancers"] = json!([{
            "tag": "worker-best",
            "selector": ["worker-node-"],
            "fallbackTag": "worker-node-1",
            "strategy": { "type": "leastPing" },
        }]);
    }
    let mut config = json!({
        // Info, so a failed dial to the Worker (e.g. "500 ... bad handshake") reaches core.log.
        "log": { "loglevel": "info" },
        "inbounds": [{
            "tag": "worker-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": false },
        }],
        "outbounds": outbounds,
        "routing": routing,
    });
    if !browser {
        config["observatory"] = json!({
            "subjectSelector": ["worker-node-"],
            "probeURL": "https://www.gstatic.com/generate_204",
            "probeInterval": format!("{}s", options.probe_interval),
            "enableConcurrency": true,
        });
    }
    Ok(config.to_string())
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

fn store_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|error| format!("no application data directory: {error}"))?
        .join("worker")
        .join("deployments.json"))
}

static STORE_LOCK: Mutex<()> = Mutex::new(());

pub fn read_deployments(app: &AppHandle) -> Result<Vec<WorkerDeployment>, String> {
    let _guard = lock(&STORE_LOCK);
    read_unlocked(app)
}

fn read_unlocked(app: &AppHandle) -> Result<Vec<WorkerDeployment>, String> {
    let path = store_path(app)?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("Saved deployment records could not be read: {error}")),
    };
    let rows: Vec<WorkerDeployment> = serde_json::from_str(&text)
        .map_err(|_| "Saved deployment records could not be read. They have been kept unchanged.".to_string())?;
    for row in &rows {
        row.validate()?;
    }
    Ok(rows)
}

/// Replaces one record, or removes it when `deployment` is `None`.
pub fn write_deployment(app: &AppHandle, key: &str, deployment: Option<&WorkerDeployment>) -> Result<(), String> {
    let _guard = lock(&STORE_LOCK);
    let mut rows = read_unlocked(app)?;
    rows.retain(|row| row.key() != key);
    if let Some(deployment) = deployment {
        deployment.validate()?;
        rows.push(deployment.clone());
    }
    let path = store_path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("cannot prepare the Worker directory: {error}"))?;
    }
    let scratch = path.with_extension("json.tmp");
    let text = serde_json::to_string_pretty(&rows).map_err(|error| error.to_string())?;
    std::fs::write(&scratch, text)
        .and_then(|_| std::fs::rename(&scratch, &path))
        .map_err(|_| "Could not save the deployment record; no further changes were made".to_string())
}

pub fn find_deployment(app: &AppHandle, key: &str) -> Result<WorkerDeployment, String> {
    let rows = read_deployments(app)?;
    if let Some(found) = rows.iter().find(|row| row.key() == key) {
        return Ok(found.clone());
    }
    // As on Android: with nothing selected, the only ready deployment is the one.
    let ready: Vec<&WorkerDeployment> = rows.iter().filter(|row| row.ready).collect();
    match (key.is_empty(), ready.as_slice()) {
        (true, [only]) => Ok((*only).clone()),
        _ => Err("Choose a deployed Cloudflare Worker first".into()),
    }
}

/// Which deployment the Worker carrier connects through.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct WorkerSelection {
    /// A deployment key (`account/kind/name`); empty picks the only ready one.
    pub deployment: String,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Manifest {
    version: String,
    sha256: String,
}

fn candidates(app: &AppHandle, name: &str) -> Vec<PathBuf> {
    let mut list = Vec::new();
    if let Ok(resources) = app.path().resource_dir() {
        list.push(resources.join(name));
        list.push(resources.join("binaries").join(name));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            list.push(parent.join(name));
            list.push(parent.join("binaries").join(name));
        }
    }
    list
}

fn locate(app: &AppHandle) -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("WHITEAESTHER_XRAY_PATH") {
        if !path.trim().is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    candidates(app, XRAY_FILENAME)
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| "The Worker engine is missing from this build".to_string())
}

/// Finds Xray and proves it is the build this app was packaged with.
fn verified_engine(app: &AppHandle) -> Result<PathBuf, String> {
    let binary = locate(app)?;
    let mut manifest_paths = vec![binary.with_file_name(MANIFEST_FILENAME)];
    manifest_paths.extend(candidates(app, MANIFEST_FILENAME));
    let manifest: Manifest = manifest_paths
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .ok_or("The Worker engine manifest is missing from this build")
        .and_then(|text| serde_json::from_str(&text).map_err(|_| "The Worker engine manifest cannot be read"))?;
    verify_engine(&binary, &manifest.version, &manifest.sha256)?;
    Ok(binary)
}

pub(crate) fn verify_engine(binary: &std::path::Path, version: &str, sha256: &str) -> Result<(), String> {
    let bytes = std::fs::read(binary).map_err(|error| format!("cannot read the Worker engine: {error}"))?;
    let digest: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    if !digest.eq_ignore_ascii_case(sha256) {
        return Err("The Worker engine does not match the checksum this build was packaged with".into());
    }
    let mut command = Command::new(binary);
    command.arg("version").stdin(Stdio::null()).stderr(Stdio::null());
    crate::core_supervisor::hide_console(&mut command);
    let output = command.output().map_err(|error| format!("cannot start the Worker engine: {error}"))?;
    let printed = String::from_utf8_lossy(&output.stdout);
    if !printed.starts_with(&format!("Xray {version} ")) {
        return Err(format!("The Worker engine reports an unexpected version: {}", printed.lines().next().unwrap_or("")));
    }
    Ok(())
}

pub fn is_available(app: &AppHandle) -> bool {
    locate(app).is_ok()
}

fn free_port() -> Result<u16, String> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .map_err(|error| format!("no free loopback port: {error}"))
}

fn listening(port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), Duration::from_millis(200)).is_ok()
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerSnapshot {
    /// "idle", "connecting", "connected", "error".
    pub state: String,
    pub socks_port: Option<u16>,
    pub deployment: Option<String>,
    pub last_error: Option<String>,
}

struct Inner {
    child: Mutex<Option<Child>>,
    snapshot: Mutex<WorkerSnapshot>,
    config: Mutex<Option<PathBuf>>,
    generation: AtomicU64,
}

#[derive(Clone)]
pub struct Worker {
    inner: Arc<Inner>,
}

const DIALER_LABEL: &str = "worker-dialer";

impl Default for Worker {
    fn default() -> Self {
        Self::new()
    }
}

impl Worker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                child: Mutex::new(None),
                snapshot: Mutex::new(WorkerSnapshot { state: "idle".into(), ..WorkerSnapshot::default() }),
                config: Mutex::new(None),
                generation: AtomicU64::new(0),
            }),
        }
    }

    pub fn snapshot(&self) -> WorkerSnapshot {
        lock(&self.inner.snapshot).clone()
    }

    pub fn carrier(&self) -> Option<Carrier> {
        let snapshot = lock(&self.inner.snapshot);
        if snapshot.state != "connected" {
            return None;
        }
        Some(Carrier {
            kind: CarrierKind::Worker,
            socks: SocketAddr::from((Ipv4Addr::LOCALHOST, snapshot.socks_port?)),
            // Many candidate edges, chosen by Xray's balancer; the process rule exempts it.
            endpoint: None,
            carries_quic: false,
        })
    }

    pub fn is_alive(&self) -> bool {
        match lock(&self.inner.child).as_mut() {
            Some(child) => !matches!(child.try_wait(), Ok(Some(_))),
            None => false,
        }
    }

    /// Starts Xray for `selection` and returns once traffic has crossed it.
    pub fn start(&self, app: &AppHandle, selection: &WorkerSelection) -> Result<SocketAddr, String> {
        self.stop(app);
        let generation = self.inner.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let deployment = find_deployment(app, &selection.deployment)?;
        if !deployment.ready {
            return Err("Finish deploying before connecting".into());
        }
        *lock(&self.inner.snapshot) = WorkerSnapshot {
            state: "connecting".into(),
            deployment: Some(deployment.key()),
            ..WorkerSnapshot::default()
        };
        match self.launch(app, &deployment, generation) {
            Ok(address) => {
                let mut snapshot = lock(&self.inner.snapshot);
                snapshot.state = "connected".into();
                snapshot.socks_port = Some(address.port());
                drop(snapshot);
                app.state::<CoreSupervisor>().record(
                    "worker",
                    "info",
                    format!("The Worker passed its connection test; SOCKS listener on {address}"),
                );
                Ok(address)
            }
            Err(error) => {
                let error = deployment.redact(&error);
                self.stop(app);
                let mut snapshot = lock(&self.inner.snapshot);
                snapshot.state = "error".into();
                snapshot.last_error = Some(error.clone());
                Err(error)
            }
        }
    }

    fn launch(&self, app: &AppHandle, deployment: &WorkerDeployment, generation: u64) -> Result<SocketAddr, String> {
        let binary = verified_engine(app)?;
        let port = free_port()?;
        let browser = deployment.options.mode == WorkerMode::Browser;
        let dialer_port = if browser { free_port()? } else { 0 };

        let directory = app
            .path()
            .app_data_dir()
            .map_err(|error| format!("no application data directory: {error}"))?
            .join("worker")
            .join("runtime");
        std::fs::create_dir_all(&directory).map_err(|error| format!("cannot prepare the Worker directory: {error}"))?;
        let config = directory.join(format!("connection-{generation}.json"));
        std::fs::write(&config, render_config(deployment, port)?)
            .map_err(|error| format!("cannot write the Worker config: {error}"))?;
        *lock(&self.inner.config) = Some(config.clone());

        let mut command = Command::new(&binary);
        command
            .arg("run")
            .arg("-config")
            .arg(&config)
            .current_dir(&directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if browser {
            command.env("xray.browser.dialer", format!("127.0.0.1:{dialer_port}"));
        }
        crate::core_supervisor::hide_console(&mut command);
        let mut child = command.spawn().map_err(|error| format!("cannot start the Worker engine: {error}"))?;
        for stream in [child.stdout.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>), child.stderr.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>)].into_iter().flatten() {
            let app = app.clone();
            let deployment = deployment.clone();
            thread::spawn(move || {
                for line in BufReader::new(stream).lines() {
                    let Ok(line) = line else { break };
                    let text: String = deployment.redact(&line).chars().take(500).collect();
                    app.state::<CoreSupervisor>().record("worker", "info", text);
                }
            });
        }
        {
            let mut guard = lock(&self.inner.child);
            if self.inner.generation.load(Ordering::SeqCst) != generation {
                let _ = child.kill();
                let _ = child.wait();
                return Err("The Worker was stopped while it was starting".into());
            }
            *guard = Some(child);
        }

        let deadline = Instant::now() + START_TIMEOUT;
        let running = || self.inner.generation.load(Ordering::SeqCst) == generation && self.is_alive();
        while !listening(if browser { dialer_port } else { port }) {
            if !running() {
                return Err("Worker engine stopped before opening its listener".into());
            }
            if Instant::now() > deadline {
                return Err("The Worker did not pass its connection test before the timeout".into());
            }
            thread::sleep(Duration::from_millis(100));
        }
        if browser {
            open_dialer(app, dialer_port)?;
        }
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        loop {
            if !running() {
                return Err("Worker engine stopped during connection testing".into());
            }
            let give_up = || Instant::now() > deadline || !running();
            match crate::carrier_probe::answers_any(address, &PROBE_TARGETS, &give_up) {
                Ok(()) => return Ok(address),
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(500)),
                Err(reason) => return Err(format!("The Worker did not pass its connection test before the timeout ({reason})")),
            }
        }
    }

    pub fn stop(&self, app: &AppHandle) {
        self.inner.generation.fetch_add(1, Ordering::SeqCst);
        if let Some(mut child) = lock(&self.inner.child).take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(config) = lock(&self.inner.config).take() {
            let _ = std::fs::remove_file(config);
        }
        if let Some(window) = app.get_webview_window(DIALER_LABEL) {
            let _ = window.destroy();
        }
        *lock(&self.inner.snapshot) = WorkerSnapshot { state: "idle".into(), ..WorkerSnapshot::default() };
    }
}

/// Opens Xray's Browser Dialer page in a hidden webview.
///
/// The webview's own TLS stack then opens the WebSocket to the Worker, which is
/// the point of the mode. The window is held to that one origin: navigation
/// elsewhere is refused, and it has no capability, so it cannot reach the app's
/// IPC. The patched dialer accepts only this origin and its own token.
fn open_dialer(app: &AppHandle, port: u16) -> Result<(), String> {
    let origin = format!("http://127.0.0.1:{port}/");
    let url: tauri::Url = origin.parse().map_err(|_| "Invalid dialer address".to_string())?;
    let allowed = url.clone();
    if let Some(window) = app.get_webview_window(DIALER_LABEL) {
        let _ = window.destroy();
    }
    tauri::WebviewWindowBuilder::new(app, DIALER_LABEL, tauri::WebviewUrl::External(url))
        .title("WhiteAesther Browser Dialer")
        .visible(false)
        .skip_taskbar(true)
        .focused(false)
        .on_navigation(move |next| next.as_str() == allowed.as_str())
        .build()
        .map(|_| ())
        .map_err(|error| format!("cannot open the Browser Dialer: {error}"))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn deployment(mode: WorkerMode) -> WorkerDeployment {
        let mut deployment = WorkerDeployment {
            account_id: "0123456789abcdef0123456789abcdef".into(),
            name: "whiteaesther-test".into(),
            pages: false,
            uuid: "12345678-1234-4234-8234-123456789abc".into(),
            host: "whiteaesther-test.example.workers.dev".into(),
            relay: String::new(),
            created: true,
            ready: true,
            options: WorkerOptions::default(),
            custom_domain: String::new(),
            version: 1,
            domain_pending: false,
            dns_zone: String::new(),
            dns_record: String::new(),
        };
        deployment.options.mode = mode;
        deployment
    }

    #[test]
    fn new_names_are_neutral_and_old_names_stay_valid() {
        for _ in 0..50 {
            let fresh = WorkerDeployment::new("0123456789abcdef0123456789abcdef", false, "").unwrap();
            assert!(!fresh.name.contains("aesther"), "{}", fresh.name);
            assert_eq!(fresh.name.split('-').count(), 3, "{}", fresh.name);
        }
        let mut old = deployment(WorkerMode::Normal);
        old.name = format!("whiteaesther-{}", random_uuid().replace('-', ""));
        assert!(old.validate().is_ok());
        for bad in ["", "-x", "x-", "Upper", "a/b", &"a".repeat(54)] {
            old.name = bad.into();
            assert!(old.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn normal_mode_balances_every_address_and_port_by_latency() {
        let mut d = deployment(WorkerMode::Normal);
        d.options.ports = vec![443, 8443];
        let config: Value = serde_json::from_str(&render_config(&d, 1080).unwrap()).unwrap();
        let nodes: Vec<&Value> = config["outbounds"].as_array().unwrap().iter().filter(|o| o["protocol"] == "vless").collect();
        // Host plus two clean addresses, on two ports.
        assert_eq!(nodes.len(), 6);
        assert_eq!(nodes[0]["settings"]["address"], d.host.as_str());
        assert_eq!(nodes[0]["settings"]["id"], d.uuid.as_str());
        assert_eq!(nodes[0]["streamSettings"]["tlsSettings"]["serverName"], d.host.as_str());
        assert_eq!(nodes[0]["streamSettings"]["tlsSettings"]["fingerprint"], "chrome");
        assert_eq!(nodes[0]["streamSettings"]["wsSettings"]["path"], "/?ed=2560");
        assert_eq!(config["routing"]["balancers"][0]["strategy"]["type"], "leastPing");
        assert_eq!(config["routing"]["rules"][0]["network"], "udp");
        assert_eq!(config["routing"]["rules"][0]["outboundTag"], "worker-block");
        assert_eq!(config["observatory"]["probeInterval"], "60s");
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["settings"]["udp"], false);
    }

    #[test]
    fn fragment_mode_masks_tcp_and_drops_ech_and_cdn() {
        let mut d = deployment(WorkerMode::Fragment);
        d.options.ech = true;
        d.options.custom_cdn = true;
        d.options.cdn_addresses = vec!["cdn.example.com".into()];
        d.options.cdn_host = "h.example.com".into();
        d.options.cdn_sni = "s.example.com".into();
        d.options.upstream_proxy = "relay.example.com:443".into();
        let config: Value = serde_json::from_str(&render_config(&d, 1080).unwrap()).unwrap();
        let nodes: Vec<&Value> = config["outbounds"].as_array().unwrap().iter().filter(|o| o["protocol"] == "vless").collect();
        assert_eq!(nodes.len(), 3, "no CDN or upstream candidates in fragment mode");
        let stream = &nodes[0]["streamSettings"];
        assert!(stream["tlsSettings"].get("echConfigList").is_none());
        assert_eq!(stream["finalmask"]["tcp"][0]["type"], "fragment");
        assert_eq!(stream["finalmask"]["tcp"][0]["settings"]["packets"], "tlshello");
        assert_eq!(stream["finalmask"]["tcp"][0]["settings"]["lengths"][0], "100-200");
    }

    #[test]
    fn browser_mode_uses_one_node_on_443_without_fingerprint() {
        let d = deployment(WorkerMode::Browser);
        let config: Value = serde_json::from_str(&render_config(&d, 1080).unwrap()).unwrap();
        let nodes: Vec<&Value> = config["outbounds"].as_array().unwrap().iter().filter(|o| o["protocol"] == "vless").collect();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["settings"]["port"], 443);
        assert!(nodes[0]["streamSettings"]["tlsSettings"].get("fingerprint").is_none());
        assert_eq!(config["routing"]["rules"][1]["outboundTag"], "worker-node-1");
        assert!(config.get("observatory").is_none());
        assert!(config["routing"].get("balancers").is_none());
    }

    #[test]
    fn ech_and_custom_cdn_apply_in_normal_mode() {
        let mut d = deployment(WorkerMode::Normal);
        d.options.ech = true;
        d.options.custom_cdn = true;
        d.options.cdn_addresses = vec!["cdn.example.com".into()];
        d.options.cdn_host = "h.example.com".into();
        d.options.cdn_sni = "s.example.com".into();
        d.options.upstream_proxy = "[2001:4860::1]:8443".into();
        let config: Value = serde_json::from_str(&render_config(&d, 1080).unwrap()).unwrap();
        let nodes: Vec<&Value> = config["outbounds"].as_array().unwrap().iter().filter(|o| o["protocol"] == "vless").collect();
        assert_eq!(nodes.len(), 5);
        let cdn = nodes.iter().find(|n| n["settings"]["address"] == "cdn.example.com").unwrap();
        assert_eq!(cdn["streamSettings"]["tlsSettings"]["serverName"], "s.example.com");
        assert_eq!(cdn["streamSettings"]["wsSettings"]["host"], "h.example.com");
        assert_eq!(nodes[0]["streamSettings"]["tlsSettings"]["echConfigList"], "cloudflare-ech.com+https://8.8.8.8/dns-query");
        assert_eq!(nodes[4]["settings"]["address"], "2001:4860::1");
        assert_eq!(nodes[4]["settings"]["port"], 8443);
    }

    #[test]
    fn a_pending_custom_domain_keeps_the_deployment_host() {
        let mut d = deployment(WorkerMode::Browser);
        d.custom_domain = "vpn.example.com".into();
        d.domain_pending = true;
        assert_eq!(d.connection_host(), d.host);
        d.domain_pending = false;
        assert_eq!(d.connection_host(), "vpn.example.com");
    }

    #[test]
    fn an_unready_deployment_renders_nothing() {
        let mut d = deployment(WorkerMode::Normal);
        d.ready = false;
        assert!(render_config(&d, 1080).is_err());
    }

    #[test]
    fn options_are_validated_like_android() {
        let ok = WorkerOptions::default();
        assert!(ok.validate().is_ok());
        let bad = |f: &dyn Fn(&mut WorkerOptions)| {
            let mut o = WorkerOptions::default();
            f(&mut o);
            o.validate().unwrap_err()
        };
        assert!(bad(&|o| o.ports = vec![80]).contains("TLS ports"));
        assert!(bad(&|o| o.ports = vec![443, 443]).contains("TLS ports"));
        assert!(bad(&|o| o.fingerprint = "opera".into()).contains("fingerprint"));
        assert!(bad(&|o| o.remote_dns = "https://1.1.1.1/dns-query".into()).contains("Cloudflare DNS"));
        assert!(bad(&|o| o.remote_dns = "udp://8.8.8.8".into()).contains("DNS"));
        assert!(bad(&|o| o.clean_addresses = vec!["bad host".into()]).contains("Invalid Worker address"));
        assert!(bad(&|o| o.custom_cdn = true).contains("Custom CDN"));
        assert!(bad(&|o| o.upstream_proxy = "relay.example.com".into()).contains("upstream"));
        assert!(bad(&|o| o.proxy_ips = vec!["a b".into()]).contains("proxy IP"));
        assert!(bad(&|o| o.fallback_url = "http://example.com".into()).contains("fallback"));
        assert!(bad(&|o| o.probe_interval = 5).contains("Probe interval"));
        assert!(bad(&|o| o.fragments[0].lengths = "300-200".into()).contains("out of bounds"));
        assert!(bad(&|o| o.fragments[0].packets = "0-3".into()).contains("packets"));
        assert!(bad(&|o| o.fragments[0].max_split = "1-2,3-4".into()).contains("maximum-split"));
        assert!(bad(&|o| o.fragments.clear()).contains("fragment entries"));
        let mut good = WorkerOptions::default();
        good.fragments[0].packets = "1-3".into();
        good.proxy_ips = vec!["relay.example.com:443".into(), "[2001:db8::1]:443".into(), "203.0.113.7".into()];
        good.fallback_url = "https://example.com/path".into();
        good.remote_dns = "tcp://8.8.8.8:53".into();
        assert!(good.validate().is_ok());
    }

    #[test]
    fn the_environment_is_what_the_script_reads() {
        let mut d = deployment(WorkerMode::Normal);
        d.relay = "relay.example.com:443".into();
        d.options.proxy_ips = vec!["relay.example.com:443".into(), "pip.example.com".into()];
        d.options.fallback_url = "https://example.com".into();
        let expected = json!({ "v": 1, "id": d.uuid, "pips": ["relay.example.com:443", "pip.example.com"], "fb": "https://example.com" });
        assert_eq!(d.environment(), base64(expected.to_string().as_bytes()));
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
        assert_eq!(base64(b"a"), "YQ==");
    }

    #[test]
    fn logs_never_carry_the_identity_or_settings() {
        let d = deployment(WorkerMode::Normal);
        let line = format!("dial {} with {}", d.uuid, d.environment());
        let redacted = d.redact(&line);
        assert!(!redacted.contains(&d.uuid));
        assert!(!redacted.contains(&d.environment()));
    }

    #[test]
    fn new_deployments_have_valid_names_and_identities() {
        let d = WorkerDeployment::new("0123456789abcdef0123456789abcdef", true, " relay.example.com:443 ").unwrap();
        assert!(d.validate().is_ok());
        assert_eq!(d.relay, "relay.example.com:443");
        assert!(valid_uuid(&d.uuid));
        assert_eq!(d.key(), format!("0123456789abcdef0123456789abcdef/pages/{}", d.name));
        assert!(WorkerDeployment::new("nothex", false, "").is_err());
        assert!(WorkerDeployment::new("0123456789abcdef0123456789abcdef", false, "bad relay").is_err());
    }

    #[test]
    fn stored_records_round_trip_in_the_android_shape() {
        let d = deployment(WorkerMode::Fragment);
        let value = serde_json::to_value(&d).unwrap();
        assert_eq!(value["accountId"], d.account_id.as_str());
        assert_eq!(value["options"]["mode"], "FRAGMENT");
        assert_eq!(value["options"]["cleanAddresses"][0], "104.17.148.22");
        let back: WorkerDeployment = serde_json::from_value(value).unwrap();
        assert_eq!(back, d);
    }

    /// `xray run -test` on all three modes when WHITEAESTHER_XRAY_PATH names a binary.
    #[test]
    fn the_pinned_engine_accepts_every_mode() {
        let Ok(binary) = std::env::var("WHITEAESTHER_XRAY_PATH") else { return };
        let directory = std::env::temp_dir().join(format!("whiteaesther-xray-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        for mode in [WorkerMode::Normal, WorkerMode::Fragment, WorkerMode::Browser] {
            let mut d = deployment(mode);
            d.options.ech = mode == WorkerMode::Normal;
            let path = directory.join(format!("{mode:?}.json").to_lowercase());
            std::fs::write(&path, render_config(&d, 10808).unwrap()).unwrap();
            if let Ok(dump) = std::env::var("WHITEAESTHER_XRAY_FIXTURES") {
                std::fs::create_dir_all(&dump).unwrap();
                std::fs::copy(&path, PathBuf::from(&dump).join(path.file_name().unwrap())).unwrap();
            }
            let output = Command::new(&binary).args(["run", "-test", "-config"]).arg(&path).output().unwrap();
            assert!(output.status.success(), "{mode:?}: {}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        }
        let _ = std::fs::remove_dir_all(&directory);
    }
}
