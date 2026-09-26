//! What got out last time, on this network.
//!
//! The race starts every way out at once, so on its own it never learns
//! anything: a network where only a split ClientHello gets through is searched
//! from the plain settings every single time, and the lane that would have
//! worked runs without the one thing that made it work. This keeps, per
//! network, the route that last carried traffic -- framing *and* tactic -- and
//! hands it to the next race as a starting point.
//!
//! ## A starting point, not a verdict
//!
//! Every lane still runs. The remembered route only decides what its own lane
//! runs *with*. A network changes under a remembered answer, so the answer
//! expires after [`FORGET_AFTER`], and when the engine was given the lead and
//! did not get out it loses that lead for [`ENGINE_RETRY_AFTER`] -- hours, not
//! the fortnight, because a negative kept that long keeps the fastest route out
//! of the lead on a network that recovered the same afternoon.
//!
//! ## Which network
//!
//! The adapter the default route leaves by: its gateway and its resolvers, and
//! the search domain or the gateway's hardware address where the platform
//! gives one. Hashed and cut short, so the file names networks without saying
//! where they are. Only the IPv4 side when there is one: the IPv6 gateways and
//! resolvers an adapter lists come and go with router advertisements, and on
//! the first machine this ran on the same Wi-Fi had two different keys two
//! hours apart. A laptop tethered to a phone is on a different network from
//! the office Wi-Fi, and this makes it look different.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How long a remembered route is offered before it has to be found again.
pub const FORGET_AFTER: Duration = Duration::from_secs(14 * 24 * 60 * 60);

/// How long the engine stays out of the lead on a network where it had the
/// lead and did not get out.
pub const ENGINE_RETRY_AFTER: Duration = Duration::from_secs(6 * 60 * 60);

/// The most networks kept. The least recently seen goes first.
pub const MAX_NETWORKS: usize = 32;

/// A route that carried traffic, as the lane that carried it actually ran.
///
/// Built from the lane's own arguments rather than its name, so a tactic the
/// user switched on by hand is remembered as part of what worked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    /// As the profile names it: `aether`, `psiphon`, `tor`.
    pub carrier: String,
    /// The engine's protocol, for an engine route.
    #[serde(default)]
    pub protocol: Option<String>,
    /// The MASQUE framing, for an engine route on MASQUE.
    #[serde(default)]
    pub transport: Option<String>,
    /// Whether the ClientHello was split.
    #[serde(default)]
    pub fragment: bool,
    /// The ECH setting the lane ran with, when it had one.
    #[serde(default)]
    pub ech: Option<String>,
}

impl Route {
    pub fn is_engine(&self) -> bool {
        self.carrier == "aether"
    }
}

/// What the engine's last failure here said would fix it.
///
/// Only the two messages that name their own remedy. Guessing at anything
/// else from failure text is how a search ends up following rules nobody can
/// predict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Remedy {
    /// The gateway demanded ECH (TLS alert 121): H3 with ECH required.
    Ech,
    /// The server name was refused (TLS alert 112): H2 with a split
    /// ClientHello.
    Fragment,
}

impl Remedy {
    /// Reads one line of the engine's log for a failure that names its remedy.
    pub fn named_in(line: &str) -> Option<Remedy> {
        let line = line.to_ascii_lowercase();
        if line.contains("ech required") || line.contains("tls alert 121") {
            Some(Remedy::Ech)
        } else if line.contains("unrecognised name") || line.contains("unrecognized name") {
            Some(Remedy::Fragment)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    #[serde(default)]
    route: Option<Route>,
    #[serde(default)]
    won_at: u64,
    #[serde(default)]
    engine_failed_at: Option<u64>,
    #[serde(default)]
    remedy: Option<Remedy>,
    #[serde(default)]
    seen_at: u64,
}

/// What the next race on a network should start from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recall {
    /// The engine route to carry into its lane, when there is one and the
    /// engine has not lost the lead here.
    pub engine_route: Option<Route>,
    /// The remedy the engine's last failure here named.
    pub remedy: Option<Remedy>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteMemory {
    #[serde(default)]
    networks: BTreeMap<String, Entry>,
}

impl RouteMemory {
    /// Reads the file, or starts empty. A file that cannot be read is a memory
    /// that has nothing in it, never a reason not to search.
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let body = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        // Written beside and moved over, so a crash mid-write leaves the old
        // memory rather than half of a new one.
        let staging = path.with_extension("json.tmp");
        std::fs::write(&staging, body).map_err(|error| error.to_string())?;
        std::fs::rename(&staging, path).map_err(|error| error.to_string())
    }

    pub fn recall(&self, network: &str, now: u64) -> Recall {
        let Some(entry) = self.networks.get(network) else {
            return Recall::default();
        };
        let fresh = |at: u64, window: Duration| now.saturating_sub(at) < window.as_secs();
        let engine_out_of_lead = entry
            .engine_failed_at
            .is_some_and(|at| fresh(at, ENGINE_RETRY_AFTER));
        let engine_route = entry
            .route
            .clone()
            .filter(|route| route.is_engine())
            .filter(|_| fresh(entry.won_at, FORGET_AFTER))
            .filter(|_| !engine_out_of_lead);
        Recall { engine_route, remedy: entry.remedy }
    }

    /// A route carried traffic here. An engine win clears the engine's
    /// failure mark and whatever remedy its last failure named: it got out,
    /// so neither is news any more.
    pub fn record_win(&mut self, network: &str, route: Route, now: u64) {
        let entry = self.networks.entry(network.to_string()).or_default();
        if route.is_engine() {
            entry.engine_failed_at = None;
            entry.remedy = None;
        }
        entry.route = Some(route);
        entry.won_at = now;
        entry.seen_at = now;
        self.prune(now);
    }

    /// The engine did not get out here. `had_lead` says whether it was running
    /// a remembered route, which is the only case that costs it the lead; a
    /// remedy is kept either way, since that is what the next race reads.
    pub fn record_engine_failure(
        &mut self,
        network: &str,
        had_lead: bool,
        remedy: Option<Remedy>,
        now: u64,
    ) {
        let entry = self.networks.entry(network.to_string()).or_default();
        if had_lead {
            entry.engine_failed_at = Some(now);
        }
        if remedy.is_some() {
            entry.remedy = remedy;
        }
        entry.seen_at = now;
        self.prune(now);
    }

    fn prune(&mut self, now: u64) {
        let window = FORGET_AFTER.as_secs();
        self.networks
            .retain(|_, entry| now.saturating_sub(entry.seen_at) < window);
        while self.networks.len() > MAX_NETWORKS {
            let Some(oldest) = self
                .networks
                .iter()
                .min_by_key(|(_, entry)| entry.seen_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.networks.remove(&oldest);
        }
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Names a network from what identifies it, without saying what that was.
fn key_of(parts: &[String]) -> Option<String> {
    if parts.iter().all(|part| part.trim().is_empty()) {
        return None;
    }
    let digest = Sha256::digest(parts.join("\n").as_bytes());
    Some(digest[..6].iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The network this machine is on now, or `None` when it cannot be told --
/// in which case nothing is remembered and nothing is recalled.
pub fn current_network() -> Option<String> {
    key_of(&stable_parts(platform::identity()?))
}

/// Leaves out every IPv6 address when there is an IPv4 gateway to go by.
fn stable_parts(parts: Vec<String>) -> Vec<String> {
    let address = |part: &String| part.split_whitespace().nth(1).map(str::to_string);
    let has_ipv4_gateway = parts.iter().any(|part| {
        part.starts_with("gw ") && address(part).is_some_and(|a| a.parse::<Ipv4Addr>().is_ok())
    });
    if !has_ipv4_gateway {
        return parts;
    }
    parts
        .into_iter()
        .filter(|part| !address(part).is_some_and(|a| a.parse::<Ipv6Addr>().is_ok()))
        .collect()
}

/// `nameserver` and `search` lines, which is all of resolv.conf that says
/// which network this is.
#[cfg(unix)]
fn resolv_conf_identity(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| line.starts_with("nameserver") || line.starts_with("search"))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

#[cfg(target_os = "linux")]
mod platform {
    use std::net::Ipv4Addr;

    /// The default route's gateway and interface, the gateway's hardware
    /// address, and the resolvers.
    pub fn identity() -> Option<Vec<String>> {
        let routes = std::fs::read_to_string("/proc/net/route").ok()?;
        let (interface, gateway) = default_route(&routes)?;
        let mut parts = vec![format!("gw {gateway}"), format!("if {interface}")];
        if let Ok(arp) = std::fs::read_to_string("/proc/net/arp") {
            if let Some(mac) = hardware_address(&arp, &gateway) {
                parts.push(format!("mac {mac}"));
            }
        }
        if let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf") {
            parts.extend(super::resolv_conf_identity(&resolv));
        }
        Some(parts)
    }

    fn default_route(table: &str) -> Option<(String, Ipv4Addr)> {
        table.lines().skip(1).find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 || fields[1] != "00000000" {
                return None;
            }
            let raw = u32::from_str_radix(fields[2], 16).ok()?;
            // The kernel prints it in host order, which is little-endian on
            // every machine this runs on.
            Some((fields[0].to_string(), Ipv4Addr::from(raw.swap_bytes())))
        })
    }

    fn hardware_address(table: &str, gateway: &Ipv4Addr) -> Option<String> {
        let wanted = gateway.to_string();
        table.lines().skip(1).find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.len() >= 4 && fields[0] == wanted && fields[3] != "00:00:00:00:00:00")
                .then(|| fields[3].to_ascii_lowercase())
        })
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::process::Command;

    /// The default route's gateway and interface, the gateway's hardware
    /// address, and the resolvers.
    pub fn identity() -> Option<Vec<String>> {
        let route = run("route", &["-n", "get", "default"])?;
        let field = |name: &str| {
            route.lines().find_map(|line| {
                line.trim()
                    .strip_prefix(name)
                    .map(|value| value.trim().to_string())
            })
        };
        let gateway = field("gateway:")?;
        let mut parts = vec![format!("gw {gateway}")];
        if let Some(interface) = field("interface:") {
            parts.push(format!("if {interface}"));
        }
        if let Some(arp) = run("arp", &["-n", &gateway]) {
            if let Some(mac) = arp.split_whitespace().skip_while(|word| *word != "at").nth(1) {
                parts.push(format!("mac {}", mac.to_ascii_lowercase()));
            }
        }
        if let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf") {
            parts.extend(super::resolv_conf_identity(&resolv));
        }
        Some(parts)
    }

    fn run(program: &str, args: &[&str]) -> Option<String> {
        let output = Command::new(program).args(args).output().ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

#[cfg(windows)]
mod platform {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    };

    /// `IfOperStatusUp`.
    const UP: i32 = 1;

    /// The gateway, resolvers and search domain of the adapter the default
    /// route leaves by: of the adapters that are up and have a gateway, the
    /// one Windows itself would prefer, by its IPv4 metric.
    pub fn identity() -> Option<Vec<String>> {
        let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        let mut size: u32 = 16 * 1024;
        let mut buffer: Vec<u64>;
        loop {
            // u64 elements, so the buffer is aligned for the structures in it.
            buffer = vec![0u64; (size as usize).div_ceil(8)];
            // SAFETY: the buffer is `size` bytes and suitably aligned; the call
            // writes at most that and says how much it wanted when it is not
            // enough.
            let result = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    flags,
                    std::ptr::null(),
                    buffer.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            match result {
                0 => break,
                // ERROR_BUFFER_OVERFLOW: `size` now holds what it needs.
                111 => continue,
                _ => return None,
            }
        }

        let mut best: Option<(u32, Vec<String>)> = None;
        let mut cursor = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cursor.is_null() {
            // SAFETY: a linked list the call just wrote into `buffer`, which
            // outlives this loop.
            let adapter = unsafe { &*cursor };
            cursor = adapter.Next;
            if adapter.OperStatus != UP || adapter.FirstGatewayAddress.is_null() {
                continue;
            }
            let mut parts = Vec::new();
            let mut gateway = adapter.FirstGatewayAddress;
            while !gateway.is_null() {
                // SAFETY: as above.
                let entry = unsafe { &*gateway };
                if let Some(address) = address_of(entry.Address.lpSockaddr) {
                    parts.push(format!("gw {address}"));
                }
                gateway = entry.Next;
            }
            let mut server = adapter.FirstDnsServerAddress;
            while !server.is_null() {
                // SAFETY: as above.
                let entry = unsafe { &*server };
                if let Some(address) = address_of(entry.Address.lpSockaddr) {
                    parts.push(format!("dns {address}"));
                }
                server = entry.Next;
            }
            let suffix = wide(adapter.DnsSuffix);
            if !suffix.is_empty() {
                parts.push(format!("search {suffix}"));
            }
            if parts.iter().all(|part| !part.starts_with("gw ")) {
                continue;
            }
            let metric = adapter.Ipv4Metric;
            if best.as_ref().is_none_or(|(current, _)| metric < *current) {
                best = Some((metric, parts));
            }
        }
        best.map(|(_, parts)| parts)
    }

    fn address_of(raw: *const SOCKADDR) -> Option<IpAddr> {
        if raw.is_null() {
            return None;
        }
        // SAFETY: the family says which of the two layouts this is.
        unsafe {
            match (*raw).sa_family {
                AF_INET => {
                    let v4 = &*(raw as *const SOCKADDR_IN);
                    Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.S_un.S_addr))))
                }
                AF_INET6 => {
                    let v6 = &*(raw as *const SOCKADDR_IN6);
                    Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte)))
                }
                _ => None,
            }
        }
    }

    fn wide(raw: *const u16) -> String {
        if raw.is_null() {
            return String::new();
        }
        // SAFETY: a NUL-terminated string inside the adapter list.
        unsafe {
            let mut length = 0;
            while *raw.add(length) != 0 {
                length += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(raw, length))
        }
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod platform {
    pub fn identity() -> Option<Vec<String>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "a1b2c3d4e5f6";
    const PHONE: &str = "0f0e0d0c0b0a";
    const DAY: u64 = 24 * 60 * 60;

    fn h2_split() -> Route {
        Route {
            carrier: "aether".into(),
            protocol: Some("masque".into()),
            transport: Some("h2".into()),
            fragment: true,
            ech: None,
        }
    }

    fn psiphon() -> Route {
        Route {
            carrier: "psiphon".into(),
            protocol: None,
            transport: None,
            fragment: false,
            ech: None,
        }
    }

    #[test]
    fn a_win_is_read_back_with_its_tactic() {
        let mut memory = RouteMemory::default();
        memory.record_win(HOME, h2_split(), 1_000);
        assert_eq!(memory.recall(HOME, 1_000 + DAY).engine_route, Some(h2_split()));
    }

    #[test]
    fn a_win_survives_the_file() {
        let path = std::env::temp_dir().join(format!("route-memory-{}.json", std::process::id()));
        let mut memory = RouteMemory::default();
        memory.record_win(HOME, h2_split(), 1_000);
        memory.save(&path).unwrap();
        let read = RouteMemory::load(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(read.recall(HOME, 1_000).engine_route, Some(h2_split()));
    }

    #[test]
    fn a_route_remembered_on_one_network_does_not_apply_on_another() {
        let mut memory = RouteMemory::default();
        memory.record_win(HOME, h2_split(), 1_000);
        assert_eq!(memory.recall(PHONE, 1_000), Recall::default());
    }

    #[test]
    fn a_route_is_forgotten_after_a_fortnight() {
        let mut memory = RouteMemory::default();
        memory.record_win(HOME, h2_split(), 1_000);
        assert!(memory.recall(HOME, 1_000 + 13 * DAY).engine_route.is_some());
        assert!(memory.recall(HOME, 1_000 + 14 * DAY).engine_route.is_none());
    }

    #[test]
    fn a_failed_lead_costs_the_engine_six_hours_not_a_fortnight() {
        let mut memory = RouteMemory::default();
        memory.record_win(HOME, h2_split(), 0);
        memory.record_engine_failure(HOME, true, None, DAY);
        assert!(memory.recall(HOME, DAY + 5 * 60 * 60).engine_route.is_none());
        assert_eq!(memory.recall(HOME, DAY + 6 * 60 * 60).engine_route, Some(h2_split()));
    }

    #[test]
    fn a_failure_without_the_lead_costs_nothing() {
        let mut memory = RouteMemory::default();
        memory.record_win(HOME, h2_split(), 0);
        memory.record_engine_failure(HOME, false, None, 10);
        assert_eq!(memory.recall(HOME, 20).engine_route, Some(h2_split()));
    }

    #[test]
    fn the_failure_mark_clears_when_the_engine_wins() {
        let mut memory = RouteMemory::default();
        memory.record_win(HOME, h2_split(), 0);
        memory.record_engine_failure(HOME, true, Some(Remedy::Ech), 10);
        memory.record_win(HOME, h2_split(), 20);
        assert_eq!(
            memory.recall(HOME, 30),
            Recall { engine_route: Some(h2_split()), remedy: None }
        );
    }

    #[test]
    fn another_carrier_winning_leaves_no_engine_route_to_carry() {
        let mut memory = RouteMemory::default();
        memory.record_win(HOME, h2_split(), 0);
        memory.record_win(HOME, psiphon(), 10);
        assert_eq!(memory.recall(HOME, 20).engine_route, None);
    }

    #[test]
    fn a_remedy_is_kept_until_the_engine_gets_out() {
        let mut memory = RouteMemory::default();
        memory.record_engine_failure(HOME, false, Some(Remedy::Fragment), 0);
        memory.record_win(HOME, psiphon(), 10);
        assert_eq!(memory.recall(HOME, 20).remedy, Some(Remedy::Fragment));
    }

    #[test]
    fn no_more_than_thirty_two_networks_are_kept() {
        let mut memory = RouteMemory::default();
        for index in 0..40u64 {
            memory.record_win(&format!("{index:012x}"), h2_split(), index);
        }
        assert_eq!(memory.networks.len(), MAX_NETWORKS);
        // The least recently seen went first.
        assert!(memory.recall(&format!("{:012x}", 0), 40).engine_route.is_none());
        assert!(memory.recall(&format!("{:012x}", 39), 40).engine_route.is_some());
    }

    #[test]
    fn only_the_two_messages_that_name_a_remedy_are_read_as_one() {
        // As `describe_early_close` in the engine's `quic.rs` words them.
        assert_eq!(
            Remedy::named_in(
                concat!(
                    "the gateway requires an ECH configuration and refused the one sent ",
                    "(TLS alert 121); set AETHER_ECH=auto, or use the H2 framing"
                )
            ),
            Some(Remedy::Ech)
        );
        assert_eq!(
            Remedy::named_in(concat!(
                "closed before the tunnel carried anything; ",
                "the gateway closed it: code=0x170 (tls: unrecognised name)"
            )),
            Some(Remedy::Fragment)
        );
        assert_eq!(
            Remedy::named_in(concat!(
                "closed before the tunnel carried anything; ",
                "the gateway closed it: code=0x128 (tls: handshake failure)"
            )),
            None
        );
        assert_eq!(Remedy::named_in("connect-ip refused"), None);
    }

    #[test]
    fn the_key_does_not_move_when_the_ipv6_entries_do() {
        // As GetAdaptersAddresses listed them on a home Wi-Fi.
        let listed: Vec<String> = [
            "gw fe80::1",
            "gw 192.168.1.1",
            "dns 192.168.1.1",
            "dns 2001:fb0:100::207:29",
            "dns 2001:fb0:100::207:49",
        ]
        .map(str::to_string)
        .to_vec();
        let fewer: Vec<String> = listed[1..3].to_vec();
        assert_eq!(key_of(&stable_parts(listed.clone())), key_of(&stable_parts(fewer)));
        // An IPv6-only network still has a key.
        let v6_only = vec!["gw fe80::1".to_string(), "dns 2001:fb0:100::207:29".to_string()];
        assert_eq!(stable_parts(v6_only.clone()), v6_only);
    }

    #[test]
    fn a_network_key_is_short_stable_and_says_nothing() {
        let parts = vec!["gw 192.168.1.1".to_string(), "dns 192.168.1.1".to_string()];
        let key = key_of(&parts).unwrap();
        assert_eq!(key.len(), 12);
        assert_eq!(key_of(&parts).unwrap(), key);
        assert!(!key.contains("192"));
        assert_ne!(key_of(&["gw 172.20.10.1".to_string()]).unwrap(), key);
        assert_eq!(key_of(&[]), None);
    }
}
