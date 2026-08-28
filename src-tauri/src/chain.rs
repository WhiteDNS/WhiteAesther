//! The second hop: routing the tunnel's output through a node of your own.
//!
//! Cloudflare WARP is explicit that it does not change your country -- it
//! egresses near you and geolocates the exit address to your region. So a user
//! in Iran connects successfully and still looks like they are in Iran. The
//! only way to change that is to add a hop after the tunnel.
//!
//! mihomo does the hop. Its `dialer-proxy` dials a node *through* another
//! proxy, so every node is reached from inside the MASQUE tunnel and the exit
//! address becomes the node's, not Cloudflare's. Verified end to end before any
//! of this was written: a real subscription moved the visible country from TH
//! to JP, and the tunnel saw the node being dialled through it.
//!
//! Two consequences of that order are worth stating, because they are the whole
//! reason it is this way round and not the other:
//!
//! - the node is dialled from inside the tunnel, so local filtering sees an
//!   ordinary Cloudflare connection and never the node's address or SNI, and
//! - a node blocked from this network is still reachable, because it is reached
//!   from Cloudflare's network rather than from here.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::core_supervisor::CoreSupervisor;

/// The name the generated config gives the first hop. Referenced by every node
/// through `dialer-proxy`, which is what puts them behind the tunnel.
const TUNNEL_PROXY: &str = "aether";
/// The group every rule points at. Selecting a node means selecting into this.
const EXIT_GROUP: &str = "exit";
/// The provider holding whatever the user pasted by hand.
const MANUAL_PROVIDER: &str = "manual";
/// The bundled rule-providers that let Iranian sites skip the exit group.
/// See [`crate::iran_routes`] for where the lists come from.
const IRAN_IP_PROVIDER: &str = "iran-ip";
const IRAN_DOMAIN_PROVIDER: &str = "iran-domain";
/// The name the TUN device takes, so a person looking at their adapter list
/// can tell what made it.
const TUN_DEVICE: &str = "WhiteAesther";
/// The tunnel's executable, named so its own packets can be kept out of the
/// device they would otherwise be fed back into.
#[cfg(windows)]
const TUNNEL_PROCESS: &str = "aether.exe";
#[cfg(not(windows))]
const TUNNEL_PROCESS: &str = "aether";
/// How long to wait for the TUN device to actually come up before giving up on
/// it. Creating an adapter and installing routes is slower than binding a port.
const TUN_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for mihomo to answer its own API before giving up on it.
const READY_TIMEOUT: Duration = Duration::from_secs(12);
const API_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(windows)]
const MIHOMO_FILENAME: &str = "mihomo.exe";
#[cfg(not(windows))]
const MIHOMO_FILENAME: &str = "mihomo";

/// A source of nodes. Either a subscription we or the user supplies, or a
/// block of pasted config URIs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChainSource {
    /// Shown in the dashboard so a node can be traced back to where it came from.
    pub name: String,
    pub url: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSettings {
    pub enabled: bool,
    /// Dial the nodes from inside the MASQUE tunnel.
    ///
    /// On by default, and worth keeping: it is what hides the node's address
    /// and SNI from the local network. But it makes the chain impossible
    /// whenever the tunnel cannot connect -- and on a network that resets
    /// MASQUE, that is always -- so it can be turned off to reach the nodes
    /// directly instead of reaching nothing at all.
    pub through_tunnel: bool,
    /// Subscription URLs. Ours ships as the first entry; the user may add more.
    pub sources: Vec<ChainSource>,
    /// Config URIs pasted by hand, one per line. mihomo converts these itself,
    /// so vless, vmess, trojan, ss, hysteria2 and the rest all work without us
    /// parsing anything.
    pub manual: String,
    /// The node last selected, so a reconnect returns to it.
    pub node: Option<String>,
}

impl Default for ChainSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            through_tunnel: true,
            sources: Vec::new(),
            manual: String::new(),
            node: None,
        }
    }
}

/// What one run of the routing engine has to do.
///
/// mihomo began here as the second hop and is now also what carries full-tunnel
/// mode and the Iran bypass, so a run is no longer described by one setting.
/// Passed as a struct rather than five positional arguments because three of
/// them are bare bools and an Option, which is exactly the shape that gets
/// silently transposed at a call site.
pub struct ChainRequest<'a> {
    /// The tunnel's SOCKS5 listener, when one is up.
    pub tunnel: Option<SocketAddr>,
    pub settings: &'a ChainSettings,
    /// Let Iranian sites go straight out. See [`crate::iran_routes`].
    pub bypass_iran_sites: bool,
    /// Capture every application's traffic through a TUN device, including the
    /// ones that ignore proxy settings entirely -- which is the only way to
    /// close a DNS leak, since a program that speaks to port 53 directly never
    /// consults a proxy.
    pub tun: bool,
    /// The gateway address the tunnel is connected to.
    ///
    /// Only used with `tun`, and required by it: with a default route pointing
    /// into the TUN device, the tunnel's own packets to its gateway would be
    /// captured and fed back into the tunnel that produced them. Naming the
    /// address here is what lets that one destination stay on the physical
    /// interface.
    pub endpoint: Option<IpAddr>,
}

impl ChainRequest<'_> {
    /// Whether a second hop is wanted, as opposed to the engine running only to
    /// hold up a TUN device.
    fn wants_exit_chain(&self) -> bool {
        self.settings.enabled
    }
}

/// A running mihomo, and the addresses it answers on.
pub struct Running {
    child: Child,
    /// Where applications and the system proxy point while the chain is up.
    pub mixed: SocketAddr,
    api: SocketAddr,
    secret: String,
    /// Whether the nodes are dialled from inside the tunnel. Decides which
    /// protocols can work at all -- see [`unusable_behind_the_tunnel`].
    through_tunnel: bool,
    /// The chain directory, so the node list can read back what the
    /// subscriptions actually contained. mihomo's API reports a protocol and a
    /// name and nothing about REALITY, and REALITY is the one thing this
    /// engine cannot use.
    home: PathBuf,
}

#[derive(Default)]
pub struct Chain {
    running: Mutex<Option<Running>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainNode {
    pub name: String,
    /// Which source supplied it.
    pub source: String,
    /// Protocol as mihomo reports it, e.g. "Vless".
    pub kind: String,
    /// Milliseconds through the tunnel, or None when the last test failed.
    pub delay: Option<u32>,
    /// Why this node cannot work as things are set up, when it cannot.
    ///
    /// A measurement that was never going to succeed is worse than no
    /// measurement: it reads as "this node is down" and sends people off to
    /// find a better one, when the node is fine and the route in front of it
    /// is what cannot carry it.
    pub unusable: Option<String>,
}

impl Chain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn address(&self) -> Option<SocketAddr> {
        self.running.lock().ok()?.as_ref().map(|running| running.mixed)
    }

    pub fn is_running(&self) -> bool {
        self.address().is_some()
    }

    /// Starts mihomo for whatever the request asks of it.
    ///
    /// Returns the address to point applications at. Fails rather than starting
    /// something that would silently bypass the tunnel, or report a TUN device
    /// that never came up.
    pub fn start(&self, app: &AppHandle, request: &ChainRequest) -> Result<SocketAddr, String> {
        self.stop();

        let settings = request.settings;
        let tunnel = request.tunnel;
        let usable: Vec<&ChainSource> = settings
            .sources
            .iter()
            .filter(|source| source.enabled && !source.url.trim().is_empty())
            .collect();
        if request.wants_exit_chain() {
            if usable.is_empty() && settings.manual.trim().is_empty() {
                return Err("add a subscription or a config before turning the chain on".into());
            }
            if settings.through_tunnel && tunnel.is_none() {
                return Err("connect first, or turn off \"dial nodes through the tunnel\"".into());
            }
        } else if !request.tun {
            // Nothing to do: no second hop wanted and no device to hold up.
            return Err("the chain has nothing to carry".into());
        }
        // Full tunnel forwards everything to the tunnel's listener, so without
        // one it would capture the machine's traffic and have nowhere to send
        // it -- which is worse than not capturing it.
        if request.tun && tunnel.is_none() {
            return Err("connect first: full tunnel has nothing to forward to".into());
        }

        let binary = locate(app)?;
        let home = app
            .path()
            .app_data_dir()
            .map_err(|error| format!("no application data directory: {error}"))?
            .join("chain");
        std::fs::create_dir_all(home.join("providers"))
            .map_err(|error| format!("cannot prepare the chain directory: {error}"))?;
        prune_provider_cache(
            &home.join("providers"),
            &usable
                .iter()
                .map(|source| provider_cache(&source.url))
                .collect::<Vec<_>>(),
        );

        // The mixed port is an address a person types into a browser, so it has
        // to be the same one tomorrow. An ephemeral port meant every launch
        // moved it, and anything configured against the last run quietly went
        // out past the hop with the old exit address.
        let mixed = preferred_port(tunnel.map_or(DEFAULT_MIXED_PORT, next_port))?;
        // The API stays ephemeral: only this process ever speaks to it.
        let api = free_port()?;
        let secret = secret();

        if !settings.manual.trim().is_empty() {
            std::fs::write(home.join("providers").join("manual.txt"), settings.manual.trim())
                .map_err(|error| format!("cannot write the pasted configs: {error}"))?;
        }
        if request.bypass_iran_sites {
            std::fs::write(
                home.join("providers").join(format!("{IRAN_IP_PROVIDER}.txt")),
                crate::iran_routes::ip_ranges_for_mihomo(),
            )
            .map_err(|error| format!("cannot write the Iran IP list: {error}"))?;
            std::fs::write(
                home.join("providers").join(format!("{IRAN_DOMAIN_PROVIDER}.txt")),
                crate::iran_routes::domains_for_mihomo(),
            )
            .map_err(|error| format!("cannot write the Iran domain list: {error}"))?;
        }

        let config = render(&RenderPlan {
            tunnel,
            mixed,
            api,
            secret: &secret,
            sources: &usable,
            manual: &settings.manual,
            bypass_iran_sites: request.bypass_iran_sites,
            exit_chain: request.wants_exit_chain(),
            tun: request.tun,
            endpoint: request.endpoint,
        });
        let config_path = home.join("config.yaml");
        std::fs::write(&config_path, config)
            .map_err(|error| format!("cannot write the chain config: {error}"))?;

        let mut command = Command::new(&binary);
        command
            .arg("-f")
            .arg(&config_path)
            .arg("-d")
            .arg(&home)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // Without this every launch flashes a console window.
            command.creation_flags(0x0800_0000);
        }

        let mut child = command
            .spawn()
            .map_err(|error| format!("cannot start the chain: {error}"))?;

        // Piped and never read is a process that blocks on its own logging once
        // the pipe fills. It also threw away the only account of what the chain
        // was doing: mihomo marks every node dead when the tunnel underneath
        // slows down, and none of that reached anyone.
        for (reader, name) in [
            (child.stdout.take().map(|out| Box::new(out) as Box<dyn Read + Send>), "chain"),
            (child.stderr.take().map(|err| Box::new(err) as Box<dyn Read + Send>), "chain"),
        ] {
            let Some(reader) = reader else {
                continue;
            };
            let app = app.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(reader).lines().map_while(Result::ok) {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let level = if line.contains("level=error") {
                        "error"
                    } else if line.contains("level=warning") {
                        "warn"
                    } else {
                        "info"
                    };
                    app.state::<CoreSupervisor>().record(name, level, line.to_string());
                }
            });
        }

        let api_address = SocketAddr::from((Ipv4Addr::LOCALHOST, api));
        let mut outcome = wait_until_ready(api_address, &secret);
        // mihomo does not exit when it cannot create the device: it logs the
        // refusal and carries on serving its mixed port, so a run that captured
        // nothing at all would otherwise look exactly like a successful one.
        // Its API reports the device's real state rather than what the config
        // asked for, which is what makes this checkable.
        if outcome.is_ok() && request.tun {
            outcome = wait_until_tun_is_up(api_address, &secret);
        }
        if let Err(error) = outcome {
            // A half-started chain must never be left behind: the system proxy
            // would point at a port nothing is listening on.
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }

        let mixed_address = SocketAddr::from((Ipv4Addr::LOCALHOST, mixed));
        *self.running.lock().map_err(|_| "the chain lock is poisoned")? =
            Some(Running {
            child,
            mixed: mixed_address,
            api: api_address,
            secret,
            through_tunnel: settings.through_tunnel,
            home: home.clone(),
        });
        Ok(mixed_address)
    }

    pub fn stop(&self) {
        let Ok(mut guard) = self.running.lock() else {
            return;
        };
        if let Some(mut running) = guard.take() {
            let _ = running.child.kill();
            let _ = running.child.wait();
        }
    }

    /// Every node from every source, with the delay each last recorded.
    pub fn nodes(&self, carries_quic: bool) -> Result<Vec<ChainNode>, String> {
        let (api, secret) = self.control()?;
        let (through_tunnel, home) = {
            let guard = self.running.lock().map_err(|_| "the chain lock is poisoned")?;
            match guard.as_ref() {
                Some(running) => (running.through_tunnel, Some(running.home.clone())),
                None => (false, None),
            }
        };
        // Read once for the whole list rather than per node: it is one small
        // file per subscription and the answer is the same for every entry.
        let reality = home.as_deref().map(reality_nodes).unwrap_or_default();
        let body = get(api, &secret, "/providers/proxies")?;
        let parsed: serde_json::Value = serde_json::from_str(&body)
            .map_err(|error| format!("the chain sent something unreadable: {error}"))?;

        let mut nodes = Vec::new();
        let Some(providers) = parsed.get("providers").and_then(|value| value.as_object()) else {
            return Ok(nodes);
        };
        for (source, provider) in providers {
            // The built-in "default" provider holds DIRECT, REJECT and the
            // group itself -- none of which are somewhere traffic can exit.
            if provider.get("vehicleType").and_then(|v| v.as_str()) == Some("Compatible") {
                continue;
            }
            let Some(list) = provider.get("proxies").and_then(|value| value.as_array()) else {
                continue;
            };
            for proxy in list {
                let Some(name) = proxy.get("name").and_then(|v| v.as_str()) else {
                    continue;
                };
                let kind = proxy.get("type").and_then(|v| v.as_str()).unwrap_or("?").to_string();
                let blocked = if reality.contains(name) {
                    Some(REALITY_UNSUPPORTED.to_string())
                } else if through_tunnel && !carries_quic {
                    unusable_behind_the_tunnel(&kind)
                } else {
                    None
                };
                nodes.push(ChainNode {
                    unusable: blocked,
                    name: name.to_string(),
                    source: source.clone(),
                    kind,
                    delay: proxy
                        .get("history")
                        .and_then(|v| v.as_array())
                        .and_then(|history| history.last())
                        .and_then(|entry| entry.get("delay"))
                        .and_then(|v| v.as_u64())
                        .filter(|delay| *delay > 0)
                        .map(|delay| delay as u32),
                });
            }
        }
        nodes.sort_by(|a, b| match (a.delay, b.delay) {
            (Some(left), Some(right)) => left.cmp(&right),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.name.cmp(&b.name),
        });
        Ok(nodes)
    }

    /// Measures one node, through the tunnel.
    ///
    /// This is the same question as "does this config work at all from here",
    /// because mihomo sends the probe down the node's `dialer-proxy` -- so a
    /// number means the config is usable behind the tunnel and a failure means
    /// it is not. Nodes supplied by a provider are not addressable through
    /// `/proxies/{name}/delay`; they answer only under their own provider.
    pub fn test(&self, source: &str, node: &str) -> Result<Option<u32>, String> {
        let (api, secret) = self.control()?;
        let path = format!(
            "/providers/proxies/{}/{}/healthcheck?url={}&timeout=8000",
            encode(source),
            encode(node),
            encode("http://www.gstatic.com/generate_204"),
        );
        match get(api, &secret, &path) {
            Ok(body) => {
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                Ok(parsed.get("delay").and_then(|v| v.as_u64()).map(|d| d as u32))
            }
            // A node that cannot be reached is an answer, not an error: it is
            // exactly what the dashboard needs to show against that node.
            Err(_) => Ok(None),
        }
    }

    /// Routes traffic through one node.
    pub fn select(&self, node: &str) -> Result<(), String> {
        let (api, secret) = self.control()?;
        let body = format!("{{\"name\":{}}}", serde_json::to_string(node).unwrap_or_default());
        put(api, &secret, &format!("/proxies/{}", encode(EXIT_GROUP)), &body)
    }

    fn control(&self) -> Result<(SocketAddr, String), String> {
        let guard = self.running.lock().map_err(|_| "the chain lock is poisoned")?;
        let running = guard.as_ref().ok_or("the chain is not running")?;
        Ok((running.api, running.secret.clone()))
    }
}

/// Said against every REALITY node, because this build cannot use one.
///
/// mihomo's REALITY client does not authenticate against current Xray servers:
/// the handshake completes, the server falls back to the site it borrows its
/// certificate from, and the connection is refused. Checked against a real
/// subscription -- three nodes, three different keys, all refused here and all
/// answering in under a second under Xray. Saying so is the honest thing; a
/// node that silently never works is worse than one labelled.
const REALITY_UNSUPPORTED: &str =
    "REALITY is not supported yet: the engine this build uses cannot authenticate with it. \
The node is fine -- it will work again here once the engine can.";

/// The node names in this chain's sources that use REALITY.
///
/// Read from the files mihomo was given rather than from mihomo, which reports
/// a name and a protocol and nothing about how the node secures itself. Both
/// shapes a provider file arrives in are covered: a base64 block of URIs, which
/// is what most panels serve, and a Clash document.
fn reality_nodes(home: &Path) -> HashSet<String> {
    let mut found = HashSet::new();
    let Ok(entries) = std::fs::read_dir(home.join("providers")) else {
        return found;
    };
    for entry in entries.flatten() {
        let Ok(raw) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        collect_reality_names(&decode_if_base64(&raw), &mut found);
    }
    found
}

/// Subscriptions arrive base64-encoded as often as not.
fn decode_if_base64(raw: &str) -> String {
    let compact: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.is_empty() || compact.contains("://") || compact.contains(':') {
        return raw.to_string();
    }
    match base64_decode(&compact) {
        Some(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        None => raw.to_string(),
    }
}

fn collect_reality_names(body: &str, into: &mut HashSet<String>) {
    // A Clash document names the node on one line and its REALITY settings on
    // the same one, because these files are written as flow mappings.
    for line in body.lines() {
        if line.contains("reality-opts") {
            if let Some(name) = clash_name(line) {
                into.insert(name);
            }
            continue;
        }
        // A URI carries its parameters in the query and its name in the
        // fragment.
        let Some((head, name)) = line.rsplit_once('#') else {
            continue;
        };
        if head.contains("security=reality") {
            into.insert(percent_decode(name.trim()));
        }
    }
}

fn clash_name(line: &str) -> Option<String> {
    let after = line.split("name:").nth(1)?;
    let name = after
        .split(',')
        .next()?
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_end_matches('}')
        .trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// The inverse of [`encode`], for names that arrive from a subscription.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const INVALID: u8 = 64;
    let value = |c: u8| -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            // Both alphabets: panels serve either, and a subscription that
            // failed to decode would silently look like it had no REALITY.
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => INVALID,
        }
    };
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut buffer = 0_u32;
    let mut held = 0;
    for byte in input.bytes() {
        if byte == b'=' {
            break;
        }
        let bits = value(byte);
        if bits == INVALID {
            return None;
        }
        buffer = (buffer << 6) | u32::from(bits);
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push((buffer >> held) as u8);
        }
    }
    Some(out)
}

/// Why a protocol cannot be carried when the nodes are dialled through the
/// tunnel, or `None` when it can.
///
/// QUIC is the whole of it. A QUIC handshake opens with a datagram padded to
/// 1280 bytes, which is 1308 bytes once the IP and UDP headers are on it, and
/// the tunnel cannot carry a packet that size: Cloudflare's connect-ip capsule
/// tops out at 1306 bytes of inner packet, measured on a live connection. Every
/// handshake attempt is therefore dropped before it leaves, which shows up as a
/// node that "does not answer" no matter how healthy it is -- both ends were
/// checked here, and the same node answers in 800ms when it is dialled
/// directly.
///
/// Matched on the protocol names mihomo reports, lowercased.
fn unusable_behind_the_tunnel(kind: &str) -> Option<String> {
    matches!(
        kind.to_ascii_lowercase().as_str(),
        "hysteria" | "hysteria2" | "tuic"
    )
    .then(|| {
        format!(
            "{kind} runs over QUIC, which needs a bigger packet than a MASQUE tunnel can carry. Switch the protocol to WireGuard under Routes and transports, or turn off \"Dial nodes through the tunnel\" there."
        )
    })
}

impl Drop for Chain {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Builds the config.
///
/// `dialer-proxy` is set per provider rather than per node, which is what lets
/// a subscription of any size arrive without us parsing or rewriting a single
/// entry: every node it carries inherits the tunnel.
///
/// `proxy` is a different question and has to be answered differently. It names
/// the route mihomo fetches the subscription *itself* over, and leaving it
/// unset sends that request through the rules -- which is `MATCH,exit`, so the
/// only way to learn about the nodes was to already be running through one of
/// them. On this subscription that failed every time (`pull error: ... EOF`),
/// and a provider that cannot refresh keeps serving whatever it cached last,
/// which is how the list ended up one node long and belonging to a subscription
/// the user had already replaced. Pointing the fetch at the tunnel is what
/// makes it independent of the hop it is trying to configure, and it still
/// never leaves the machine in the clear.
/// Everything one generated config depends on.
///
/// A struct because the list outgrew what anyone can read positionally: four of
/// these are bools and Options of the same shape, and transposing two of them
/// would produce a config that is valid, silently wrong, and routes traffic.
struct RenderPlan<'a> {
    tunnel: Option<SocketAddr>,
    mixed: u16,
    api: u16,
    secret: &'a str,
    sources: &'a [&'a ChainSource],
    manual: &'a str,
    bypass_iran_sites: bool,
    /// Whether a second hop is being set up, or the engine is only holding up
    /// a TUN device in front of the tunnel.
    exit_chain: bool,
    tun: bool,
    endpoint: Option<IpAddr>,
}

impl Default for RenderPlan<'_> {
    fn default() -> Self {
        Self {
            tunnel: None,
            mixed: DEFAULT_MIXED_PORT,
            api: 1821,
            secret: "",
            sources: &[],
            manual: "",
            bypass_iran_sites: false,
            exit_chain: true,
            tun: false,
            endpoint: None,
        }
    }
}

fn render(plan: &RenderPlan) -> String {
    let RenderPlan {
        tunnel,
        mixed,
        api,
        secret,
        sources,
        manual,
        bypass_iran_sites,
        exit_chain,
        tun,
        endpoint,
    } = *plan;
    let mut config = String::new();
    config.push_str(&format!("mixed-port: {mixed}\n"));
    // Loopback only, with a secret that changes every run. Without both, any
    // web page the user opens could drive this API and reroute their traffic.
    config.push_str(&format!("external-controller: 127.0.0.1:{api}\n"));
    config.push_str(&format!("secret: {}\n", serde_json::to_string(secret).unwrap_or_default()));
    // info, not warning: a node list where every entry reads dead is explained
    // by the health-check lines, and those are info. They cost a few lines a
    // minute and now go to the app log rather than an undrained pipe.
    config.push_str("mode: rule\nlog-level: info\nipv6: true\n");

    // The device that makes this a full tunnel rather than a proxy. Written
    // line by line because it is YAML, where one wrong space changes what it
    // means.
    if tun {
        config.push_str("tun:\n");
        config.push_str("  enable: true\n");
        // gVisor rather than the system stack: it needs no kernel driver
        // beyond the adapter itself, and it is the stack mihomo treats as its
        // portable default.
        config.push_str("  stack: gvisor\n");
        config.push_str(&format!("  device: {TUN_DEVICE}\n"));
        // Installs the default route. Without it the device exists and nothing
        // is sent to it.
        config.push_str("  auto-route: true\n");
        config.push_str("  auto-detect-interface: true\n");
        // `strict-route` is deliberately not set, and this is the reason.
        //
        // It exists to force in the traffic `auto-route` misses -- a DNS query
        // to a resolver on the local network never crosses the default route,
        // so it is never hijacked -- which is exactly the hole this mode is
        // meant to close. But it closes it by refusing to let anything leave
        // except through the device, and the tunnel this whole arrangement
        // feeds is a *separate process* whose packets have to reach a gateway
        // on the open internet. Turning it on took the connection out
        // entirely once the exit chain was in the path.
        //
        // The exemption below is the same idea done at a layer that can tell
        // the difference. Revisit only with a way to test it: the failure is
        // total loss of connectivity, which is not something to guess at.
        //
        // A program that speaks to port 53 itself never consults a proxy, so
        // this is what stops the query leaving in the clear alongside a
        // tunnelled connection. Both transports: a resolver that is refused
        // over UDP will retry the same query over TCP.
        config.push_str("  dns-hijack:\n    - any:53\n    - tcp://any:53\n");
    }

    // Resolvers live inside the chain. A query that escapes to the local
    // network names the destination even when the traffic itself does not.
    config.push_str("dns:\n");
    config.push_str("  enable: true\n");
    config.push_str("  ipv6: true\n");
    config.push_str("  enhanced-mode: fake-ip\n");
    config.push_str("  fake-ip-range: 198.18.0.1/16\n");
    // Names that must resolve to something real. A machine on the local
    // network handed a fake address is simply unreachable, and the person
    // trying to print blames the tunnel, correctly.
    config.push_str("  fake-ip-filter:\n    - \"*.lan\"\n    - \"*.local\"\n    - \"*.home.arpa\"\n");
    // Plain addresses, used only to resolve the hostnames of the resolvers
    // below. Without it a DoH URL written as a name cannot be looked up
    // without already having a resolver.
    config.push_str("  default-nameserver:\n    - 1.1.1.1\n    - 9.9.9.9\n");
    config.push_str("  nameserver:\n    - https://1.1.1.1/dns-query\n    - https://dns.google/dns-query\n");
    // Resolving the proxies' own hostnames cannot go through the proxies: that
    // is the same circle as fetching a subscription through the node it
    // describes.
    config.push_str("  proxy-server-nameserver:\n    - https://1.1.1.1/dns-query\n");
    // Anything mihomo does resolve itself follows the same rules as the
    // traffic. Without this those queries take a direct route regardless of
    // where the traffic goes, so the resolver and the exit end up in different
    // countries -- which is both a leak and a mismatch anyone can see.
    config.push_str("  respect-rules: true\n");

    // Declared only when there is a tunnel to declare. A socks5 proxy pointing
    // at a port nothing is listening on would fail every node it fronted.
    let (through, fetch_through) = match tunnel {
        Some(address) => {
            config.push_str(&format!(
                "proxies:\n  - {{name: {TUNNEL_PROXY}, type: socks5, server: {}, port: {}, udp: true}}\n",
                address.ip(),
                address.port()
            ));
            (
                format!("\n    dialer-proxy: {TUNNEL_PROXY}"),
                format!("\n    proxy: {TUNNEL_PROXY}"),
            )
        }
        None => (String::new(), String::new()),
    };

    let mut names: Vec<String> = Vec::new();
    if exit_chain && (!sources.is_empty() || !manual.trim().is_empty()) {
        config.push_str("proxy-providers:\n");
    }
    for (index, source) in sources.iter().enumerate().filter(|_| exit_chain) {
        let key = format!("source{index}");
        names.push(key.clone());
        config.push_str(&format!(
            "  {key}:\n    type: http\n    url: {}\n    interval: 3600\n    \
             path: ./providers/{}.yaml{fetch_through}{through}\n    \
             health-check: {{enable: true, url: \"http://www.gstatic.com/generate_204\", \
             interval: 300, lazy: true}}\n",
            serde_json::to_string(&source.url).unwrap_or_default(),
            provider_cache(&source.url),
        ));
    }
    if exit_chain && !manual.trim().is_empty() {
        names.push(MANUAL_PROVIDER.into());
        config.push_str(&format!(
            "  {MANUAL_PROVIDER}:\n    type: file\n    path: ./providers/manual.txt{through}\n    \
             health-check: {{enable: true, \
             url: \"http://www.gstatic.com/generate_204\", interval: 300, lazy: true}}\n"
        ));
    }

    if exit_chain {
        config.push_str(&format!(
            "proxy-groups:\n  - name: {EXIT_GROUP}\n    type: select\n    use: [{}]\n",
            names.join(", ")
        ));
    }

    // Where everything that matches nothing else ends up: the second hop when
    // there is one, otherwise the tunnel itself. A rule that let it take a
    // direct route would put that traffic on the local network in the clear.
    let catch_all = if exit_chain { EXIT_GROUP } else { TUNNEL_PROXY };

    if bypass_iran_sites {
        // Written line by line rather than as one long literal: this is YAML,
        // where a stray space changes the meaning, and a single string with
        // embedded newlines hides that from review.
        config.push_str("rule-providers:\n");
        for (name, behavior) in
            [(IRAN_DOMAIN_PROVIDER, "domain"), (IRAN_IP_PROVIDER, "ipcidr")]
        {
            config.push_str(&format!("  {name}:\n"));
            config.push_str("    type: file\n");
            config.push_str(&format!("    behavior: {behavior}\n"));
            config.push_str("    format: text\n");
            config.push_str(&format!("    path: ./providers/{name}.txt\n"));
        }
    }

    config.push_str("rules:\n");

    // First, before anything else can claim it: the tunnel's own traffic.
    //
    // `auto-route` points the default route at the TUN device, and the tunnel
    // is an ordinary program on this machine -- so its packets to Cloudflare
    // would be captured and handed back to the tunnel that produced them. The
    // loop is silent and total: nothing reaches the network, including the
    // traffic that would have told anyone why.
    //
    // Matched on the process rather than on the gateway address, because the
    // address is the wrong thing to key on twice over: it is not known at all
    // until the tunnel has picked one, and it changes under us every time the
    // tunnel reconnects somewhere else -- either of which leaves the rule
    // matching nothing and the loop closed. The process is the same process
    // throughout. The address rule stays as a second line of defence for a
    // platform where process matching is unavailable.
    if tun {
        config.push_str(&format!("  - PROCESS-NAME,{TUNNEL_PROCESS},DIRECT\n"));
        if let Some(address) = endpoint {
            let prefix = if address.is_ipv4() { 32 } else { 128 };
            // `no-resolve` because the address is already an address, and
            // resolving it would be one more DNS query going through the
            // device this rule exists to keep it out of.
            config.push_str(&format!("  - IP-CIDR,{address}/{prefix},DIRECT,no-resolve\n"));
        }
    }

    // The local network, which is not somewhere a tunnel can take you.
    //
    // With a default route into the device, a request to a printer, a NAS or
    // the router itself is captured like everything else and sent to an exit
    // node that has no path back to it. Two things follow, and both were seen:
    // the local machine is simply unreachable, and a DNS query aimed at the
    // router fails there and is retried by Windows on whatever other adapter
    // it can find -- which is how a query escapes a tunnel that looked
    // complete. Windows Delivery Optimization alone was pushing peer transfers
    // for 192.168.x addresses through the exit.
    //
    // `no-resolve` throughout: these are addresses already, and resolving them
    // would be a DNS query made to decide where a DNS query should go.
    //
    // The fake-ip range is deliberately absent. It is not a real destination:
    // it is how the engine hands a name back to itself, and sending it direct
    // would break every name it stands for.
    for range in [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        // Link-local, carrier-grade NAT, and multicast: local in the same
        // sense, and equally unroutable from an exit node.
        "169.254.0.0/16",
        "100.64.0.0/10",
        "224.0.0.0/4",
    ] {
        config.push_str(&format!("  - IP-CIDR,{range},DIRECT,no-resolve
"));
    }
    for range in ["fc00::/7", "fe80::/10"] {
        config.push_str(&format!("  - IP-CIDR6,{range},DIRECT,no-resolve
"));
    }

    // Iranian sites are the one deliberate exception to everything going out
    // through the tunnel: filtering only applies to traffic that looks like it
    // left the country, so a site already reachable directly gains nothing
    // from the exit and only pays for its bandwidth.
    if bypass_iran_sites {
        config.push_str("  - DOMAIN-SUFFIX,ir,DIRECT\n");
        config.push_str(&format!("  - RULE-SET,{IRAN_DOMAIN_PROVIDER},DIRECT\n"));
        config.push_str(&format!("  - RULE-SET,{IRAN_IP_PROVIDER},DIRECT\n"));
    }

    config.push_str(&format!("  - MATCH,{catch_all}\n"));
    config
}

fn locate(app: &AppHandle) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("WHITEAESTHER_MIHOMO_PATH") {
        if !path.trim().is_empty() {
            candidates.push(PathBuf::from(path));
        }
    }
    if let Ok(resources) = app.path().resource_dir() {
        candidates.push(resources.join(MIHOMO_FILENAME));
        candidates.push(resources.join("binaries").join(MIHOMO_FILENAME));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join(MIHOMO_FILENAME));
        }
    }
    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err("the chain engine is missing from this installation".into())
}

/// A port the OS says is free right now.
///
/// There is a gap between letting go of the port and mihomo binding it. Nothing
/// on a desktop is racing for a random high port, and the alternative -- fixed
/// ports -- collides with whatever else the machine is already running.
/// The mixed port used when there is no tunnel to derive one from.
const DEFAULT_MIXED_PORT: u16 = 1820;

/// One above the tunnel's own port, so the two read as a pair.
fn next_port(tunnel: SocketAddr) -> u16 {
    tunnel.port().checked_add(1).unwrap_or(DEFAULT_MIXED_PORT)
}

/// The cache file a subscription's nodes are kept in, named after the URL.
///
/// Named after the position in the list, they were not: a user who replaced a
/// subscription got a provider pointed at the new URL and a cache file left
/// over from the old one, and every failed refresh served the previous
/// subscription's nodes as though they were the new ones. A name derived from
/// the URL cannot collide that way -- a different subscription is a different
/// file, and an unreadable new one shows as empty rather than as someone
/// else's.
fn provider_cache(url: &str) -> String {
    // FNV-1a. Not a security boundary -- this only has to be stable across runs
    // and safe to put in a path.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in url.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Deletes cache files for subscriptions that are no longer configured.
///
/// Without this the directory only ever grows, and a subscription removed today
/// leaves its nodes on disk to be picked up if its URL is ever added back.
fn prune_provider_cache(directory: &std::path::Path, keep: &[String]) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("yaml") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        if !keep.iter().any(|name| name == stem) {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Takes `want` when it is free, and any free port when it is not.
///
/// Falling back rather than failing matters: something else holding one port is
/// a reason to move, not a reason to leave the user without a second hop.
fn preferred_port(want: u16) -> Result<u16, String> {
    match TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, want))) {
        Ok(listener) => {
            drop(listener);
            Ok(want)
        }
        Err(_) => free_port(),
    }
}

fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .map_err(|error| format!("no free local port: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("no free local port: {error}"))?
        .port();
    drop(listener);
    Ok(port)
}

fn secret() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    format!("{:x}{:x}", nanos, std::process::id())
}

/// Waits for mihomo to answer, which is the only proof it actually came up.
fn wait_until_ready(api: SocketAddr, secret: &str) -> Result<(), String> {
    let deadline = Instant::now() + READY_TIMEOUT;
    let mut last = String::from("the chain did not start");
    while Instant::now() < deadline {
        match get(api, secret, "/version") {
            Ok(_) => return Ok(()),
            Err(error) => last = error,
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(format!("the chain did not become ready: {last}"))
}

/// Waits for the TUN device to actually exist, rather than for mihomo to have
/// been asked for one.
///
/// The distinction is the whole point. mihomo does not exit when it cannot
/// create the device -- it logs `configure tun interface: Access is denied` and
/// keeps serving its mixed port -- so the process being alive says nothing
/// about whether a single packet is being captured. Its API answers the real
/// question: `tun.enable` in `/configs` reports the running state, and comes
/// back `false` on a run whose config asked for `true`.
fn wait_until_tun_is_up(api: SocketAddr, secret: &str) -> Result<(), String> {
    let deadline = Instant::now() + TUN_READY_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(body) = get(api, secret, "/configs") {
            if tun_is_enabled(&body) {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(
        "the full-tunnel device did not come up. Creating a network adapter needs permission \
         this copy was not started with -- switch Full tunnel on again and accept the restart \
         when it is offered."
            .into(),
    )
}

/// Whether mihomo reports a live TUN device in its own configuration dump.
fn tun_is_enabled(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("tun")?.get("enable")?.as_bool())
        .unwrap_or(false)
}

fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn get(api: SocketAddr, secret: &str, path: &str) -> Result<String, String> {
    request(api, secret, "GET", path, None)
}

fn put(api: SocketAddr, secret: &str, path: &str, body: &str) -> Result<(), String> {
    request(api, secret, "PUT", path, Some(body)).map(|_| ())
}

/// A minimal HTTP client for the control API.
///
/// std-only, like the rest of this crate: the API is on loopback, speaks
/// HTTP/1.1, and pulling in a client stack to talk to it would be the largest
/// dependency in the project.
fn request(
    api: SocketAddr,
    secret: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<String, String> {
    let mut stream = TcpStream::connect_timeout(&api, API_TIMEOUT)
        .map_err(|error| format!("the chain is not answering: {error}"))?;
    stream.set_read_timeout(Some(API_TIMEOUT)).map_err(|e| e.to_string())?;

    let payload = body.unwrap_or("");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {api}\r\nAuthorization: Bearer {secret}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("cannot reach the chain: {error}"))?;

    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader
        .read_line(&mut status)
        .map_err(|error| format!("the chain gave no reply: {error}"))?;
    let code = status
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or("the chain gave an unreadable reply")?;

    // Go sets Content-Length only for a reply small enough to buffer, and
    // frames the rest in chunks. That is why this went unnoticed for so long:
    // /version is 35 bytes and arrives whole, so the readiness check passed and
    // the chain reported itself up, while the node list -- the one reply that is
    // always large -- reached the JSON parser with its chunk header still on the
    // front. "expected value at line 1 column 1" reads like the chain crashed,
    // not like a reply we never finished reading.
    let mut chunked = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        let lowered = line.to_ascii_lowercase();
        if let Some(value) = lowered.strip_prefix("transfer-encoding:") {
            chunked = value.contains("chunked");
        }
    }
    let rest = if chunked {
        read_chunked(&mut reader)?
    } else {
        let mut body = String::new();
        let _ = reader.read_to_string(&mut body);
        body
    };

    if !(200..300).contains(&code) {
        return Err(format!("the chain refused that request ({code})"));
    }
    Ok(rest)
}

/// Reassembles a chunked body.
///
/// Only what reading one requires: sizes are hex, may carry a `;extension`
/// this ignores, and a zero-length chunk ends the body. Trailers after it are
/// left unread, because the connection is closing anyway.
fn read_chunked<R: BufRead>(reader: &mut R) -> Result<String, String> {
    let mut body = Vec::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).map_err(|e| e.to_string())? == 0 {
            break;
        }
        let size = header.trim().split(';').next().unwrap_or_default();
        if size.is_empty() {
            continue;
        }
        let size = usize::from_str_radix(size, 16)
            .map_err(|_| "the chain framed its reply in a way we cannot read".to_string())?;
        if size == 0 {
            break;
        }
        // The length is the peer's word, not ours, and this reply is a node
        // list rather than a download.
        if body.len() + size > MAX_BODY {
            return Err("the chain sent more than we are willing to hold".into());
        }
        let mut chunk = vec![0u8; size];
        reader
            .read_exact(&mut chunk)
            .map_err(|error| format!("the chain stopped mid-reply: {error}"))?;
        body.extend_from_slice(&chunk);
        // The line break that closes the chunk.
        let mut terminator = String::new();
        let _ = reader.read_line(&mut terminator);
    }
    String::from_utf8(body).map_err(|_| "the chain sent something that is not text".into())
}

/// Eight megabytes: far beyond any node list, far below anything that matters
/// to a desktop.
const MAX_BODY: usize = 8 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    fn source(name: &str, url: &str) -> ChainSource {
        ChainSource { name: name.into(), url: url.into(), enabled: true }
    }

    fn tunnel() -> Option<SocketAddr> {
        Some("127.0.0.1:1819".parse().unwrap())
    }

    #[test]
    fn every_source_dials_through_the_tunnel() {
        // The one property the whole feature rests on. A provider without
        // dialer-proxy would reach its nodes directly, exposing them to the
        // local network and leaving the exit address unchanged.
        let sources = [source("ours", "https://example.com/a"), source("theirs", "https://example.com/b")];
        let refs: Vec<&ChainSource> = sources.iter().collect();
        let config = render(&RenderPlan { tunnel: tunnel(), mixed: 1820, api: 1821, secret: "s", sources: &refs, manual: "vless://pasted", ..Default::default() });

        let providers = config.matches("dialer-proxy: aether").count();
        assert_eq!(providers, 3, "two subscriptions and the pasted block, all behind the tunnel");
    }

    #[test]
    fn a_subscription_is_fetched_over_the_tunnel_not_over_the_hop_it_configures() {
        // Left to the rules, the fetch matched MATCH,exit and went out through
        // a node -- so the node list could only be refreshed by a node already
        // in it. Every refresh failed, the provider kept serving its last
        // cache, and the screen showed one stale node out of seven.
        let sources = [source("ours", "https://example.com/a")];
        let refs: Vec<&ChainSource> = sources.iter().collect();
        let config = render(&RenderPlan { tunnel: tunnel(), mixed: 1820, api: 1821, secret: "s", sources: &refs, ..Default::default() });
        assert!(config.contains("\n    proxy: aether"), "the fetch must name the tunnel");
        // And the nodes it carries still dial through the tunnel: these are two
        // different routes and setting one must not have replaced the other.
        assert!(config.contains("\n    dialer-proxy: aether"));
    }

    #[test]
    fn without_a_tunnel_the_fetch_names_no_proxy_at_all() {
        let sources = [source("ours", "https://example.com/a")];
        let refs: Vec<&ChainSource> = sources.iter().collect();
        let config = render(&RenderPlan { mixed: 1820, api: 1821, secret: "s", sources: &refs, ..Default::default() });
        assert!(!config.contains("proxy: aether"), "there is no tunnel to fetch through");
    }

    #[test]
    fn a_replaced_subscription_cannot_serve_the_previous_one_s_nodes() {
        // The cache file used to be named after the position in the list, so a
        // new URL inherited the old URL's nodes and served them whenever it
        // could not refresh.
        let old = [source("ours", "https://example.com/old")];
        let new = [source("ours", "https://example.com/new")];
        let old_config = render(&RenderPlan { tunnel: tunnel(), mixed: 1820, api: 1821, secret: "s", sources: &old.iter().collect::<Vec<_>>(), ..Default::default() });
        let new_config = render(&RenderPlan { tunnel: tunnel(), mixed: 1820, api: 1821, secret: "s", sources: &new.iter().collect::<Vec<_>>(), ..Default::default() });
        let path_of = |config: &str| {
            config
                .lines()
                .find_map(|line| line.trim().strip_prefix("path: ").map(ToString::to_string))
                .expect("a provider path")
        };
        assert_ne!(path_of(&old_config), path_of(&new_config));
        // Same URL, same file: a restart has to find what it already pulled.
        assert_eq!(provider_cache("https://example.com/old"), provider_cache("https://example.com/old"));
    }

    #[test]
    fn nothing_routable_is_allowed_to_take_a_direct_route() {
        // Local addresses are exempt on purpose -- an exit node has no path to
        // a printer -- so the rule is no longer "nothing is direct". It is that
        // nothing which could actually leave this network is: the catch-all
        // must be the exit, and every direct rule must name a range that is
        // unroutable from outside.
        let config = render(&RenderPlan { tunnel: tunnel(), mixed: 1820, api: 1821, secret: "s", manual: "vless://pasted", ..Default::default() });
        assert!(config.contains("MATCH,exit"));
        assert!(!config.contains("MATCH,DIRECT"), "the catch-all must never be direct");

        const LOCAL: [&str; 9] = [
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
            "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4", "fc00::/7", "fe80::/10",
        ];
        for line in config.lines().filter(|line| line.contains("DIRECT")) {
            assert!(
                LOCAL.iter().any(|range| line.contains(range)),
                "a direct rule that is not a local range would leak that traffic: {line}"
            );
        }
    }

    #[test]
    fn dns_resolves_inside_the_chain() {
        // A query that escapes names the destination even when the traffic does
        // not, which is the most common way a chain like this leaks.
        let config = render(&RenderPlan { tunnel: tunnel(), mixed: 1820, api: 1821, secret: "s", manual: "vless://x", ..Default::default() });
        assert!(config.contains("enhanced-mode: fake-ip"));
        assert!(config.contains("https://1.1.1.1/dns-query"));
        assert!(!config.contains("\n    - 8.8.8.8"), "a plain resolver would leave the chain");
    }

    #[test]
    fn the_control_api_is_never_exposed() {
        let config = render(&RenderPlan { tunnel: tunnel(), mixed: 1820, api: 1821, secret: "s3cret", manual: "vless://x", ..Default::default() });
        assert!(config.contains("external-controller: 127.0.0.1:1821"));
        assert!(config.contains("secret: \"s3cret\""));
    }

    #[test]
    fn a_disabled_source_is_left_out() {
        let mut off = source("off", "https://example.com/off");
        off.enabled = false;
        let on = source("on", "https://example.com/on");
        let refs: Vec<&ChainSource> = vec![&on];
        let config = render(&RenderPlan { tunnel: tunnel(), mixed: 1820, api: 1821, secret: "s", sources: &refs, ..Default::default() });
        assert!(config.contains("example.com/on"));
        assert!(!config.contains("example.com/off"));
        let _ = off;
    }

    #[test]
    fn full_tunnel_declares_a_device_and_hijacks_dns() {
        let config = render(&RenderPlan {
            tunnel: tunnel(),
            manual: "vless://x",
            tun: true,
            ..Default::default()
        });
        assert!(config.contains("tun:"), "the device has to be declared");
        assert!(config.contains("enable: true"));
        assert!(config.contains("auto-route: true"), "without this nothing is sent to it");
        // The reason the feature exists: a program that speaks to port 53
        // itself never consults a proxy, so only hijacking catches it.
        assert!(config.contains("dns-hijack:"), "{config}");
        assert!(config.contains("any:53"), "{config}");
    }

    #[test]
    fn full_tunnel_hijacks_dns_on_both_transports() {
        // A program that speaks to port 53 itself never consults a proxy, so
        // hijacking is what stops the query leaving in the clear beside a
        // tunnelled connection.
        let config = render(&RenderPlan {
            tunnel: tunnel(),
            manual: "vless://x",
            tun: true,
            ..Default::default()
        });
        assert!(config.contains("dns-hijack:"), "{config}");
        assert!(config.contains("- any:53"), "{config}");
        // A resolver refused over UDP retries the same query over TCP.
        assert!(config.contains("tcp://any:53"), "{config}");
    }

    #[test]
    fn dns_that_the_engine_resolves_itself_follows_the_traffic() {
        // Without this, those queries take a direct route whatever the traffic
        // does -- so the resolver and the exit end up in different countries,
        // which is both a leak and a mismatch anyone can see on a leak test.
        let config = render(&RenderPlan { tunnel: tunnel(), manual: "vless://x", ..Default::default() });
        assert!(config.contains("respect-rules: true"), "{config}");
        // Resolving the proxies' own names cannot go through the proxies.
        assert!(config.contains("proxy-server-nameserver:"), "{config}");
        // And a name on the local network must resolve to something real, or
        // the printer is unreachable and the tunnel gets the blame.
        assert!(config.contains("fake-ip-filter:"), "{config}");
        assert!(config.contains("*.lan"), "{config}");
    }

    #[test]
    fn without_full_tunnel_no_device_is_declared() {
        let config = render(&RenderPlan {
            tunnel: tunnel(),
            manual: "vless://x",
            ..Default::default()
        });
        assert!(!config.contains("tun:"));
        assert!(!config.contains("dns-hijack"));
    }

    #[test]
    fn the_tunnels_own_gateway_is_kept_out_of_the_device_it_feeds() {
        // The loop this prevents is silent and total: auto-route sends the
        // default route into the device, the tunnel is an ordinary program on
        // this machine, and its packets to the gateway would be captured and
        // handed back to the tunnel that produced them -- taking everything
        // down including whatever would have explained why.
        let config = render(&RenderPlan {
            tunnel: tunnel(),
            manual: "vless://x",
            tun: true,
            endpoint: Some("162.159.198.2".parse().unwrap()),
            ..Default::default()
        });
        assert!(
            config.contains("- IP-CIDR,162.159.198.2/32,DIRECT,no-resolve"),
            "{config}"
        );
        // The process rule is what actually holds it: the address is unknown
        // until a gateway has been picked and changes on every reconnect, so a
        // rule keyed on it alone leaves the loop closed exactly when it matters.
        assert!(config.contains("- PROCESS-NAME,aether.exe,DIRECT"), "{config}");
        // And it has to be the first rule, or a rule above it could claim the
        // tunnel first and the loop closes anyway.
        let rules = config.split("rules:\n").nth(1).expect("a rules section");
        let first = rules.lines().next().expect("a first rule");
        assert!(first.contains("PROCESS-NAME"), "the tunnel must be exempted first: {first}");
    }

    #[test]
    fn the_local_network_is_never_sent_to_an_exit_node() {
        // An exit node has no path back to a printer, a NAS or the router. Two
        // things follow and both were seen on a live machine: the local
        // machine is unreachable, and a DNS query aimed at the router fails
        // there and is retried by Windows on some other adapter -- which is
        // how a query escapes a tunnel that looked complete.
        let config = render(&RenderPlan {
            tunnel: tunnel(),
            manual: "vless://x",
            tun: true,
            ..Default::default()
        });
        for range in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"] {
            assert!(
                config.contains(&format!("- IP-CIDR,{range},DIRECT,no-resolve")),
                "{range} must stay off the exit: {config}"
            );
        }
        assert!(config.contains("- IP-CIDR6,fe80::/10,DIRECT,no-resolve"), "{config}");

        // The fake-ip range must never be direct: it is not a destination, it
        // is how the engine hands a name back to itself, and sending it out
        // would break every name it stands for.
        assert!(!config.contains("- IP-CIDR,198.18"), "{config}");

        // And they have to be checked before the catch-all, or the catch-all
        // claims them first and none of this matters.
        let rules = config.split("rules:
").nth(1).expect("a rules section");
        let private = rules.find("192.168.0.0/16").expect("the private rule");
        let catch_all = rules.find("MATCH,").expect("the catch-all");
        assert!(private < catch_all, "private ranges must be decided first");
    }

    #[test]
    fn the_tunnel_is_exempted_even_when_no_gateway_is_known_yet() {
        // The address is not known until a gateway has been picked, and it
        // changes under us on every reconnect. Keyed on it alone the rule
        // matches nothing, and every packet the tunnel sends is handed back to
        // the tunnel -- so the exemption cannot depend on knowing it.
        let config = render(&RenderPlan {
            tunnel: tunnel(),
            manual: "vless://x",
            tun: true,
            endpoint: None,
            ..Default::default()
        });
        assert!(config.contains("- PROCESS-NAME,aether.exe,DIRECT"), "{config}");
        // The gateway rule is the one that cannot be written without an
        // address. The local ranges are constants and are always there.
        assert!(
            !config.contains(",DIRECT,no-resolve
  - IP-CIDR,162"),
            "no gateway rule without a gateway: {config}"
        );
        assert_eq!(
            config.matches("IP-CIDR,").count(),
            7,
            "only the seven local IPv4 ranges: {config}"
        );
    }

    #[test]
    fn strict_route_is_never_set() {
        // It refuses to let anything leave except through the device, and the
        // tunnel this arrangement feeds is a separate process that has to
        // reach a gateway on the open internet. With it on, the connection
        // went away entirely once the exit chain was in the path.
        let config = render(&RenderPlan {
            tunnel: tunnel(),
            manual: "vless://x",
            tun: true,
            endpoint: Some("162.159.198.2".parse().unwrap()),
            ..Default::default()
        });
        assert!(!config.contains("strict-route"), "{config}");
    }

    #[test]
    fn an_ipv6_gateway_gets_the_right_prefix_length() {
        // /32 on an IPv6 address would silently exempt a sixteenth of the
        // internet rather than one host.
        let config = render(&RenderPlan {
            tunnel: tunnel(),
            manual: "vless://x",
            tun: true,
            endpoint: Some("2606:4700:d0::a29f:c602".parse().unwrap()),
            ..Default::default()
        });
        assert!(config.contains("- IP-CIDR,2606:4700:d0::a29f:c602/128,DIRECT,no-resolve"), "{config}");
    }

    #[test]
    fn full_tunnel_without_a_second_hop_sends_everything_to_the_tunnel() {
        // The engine runs to hold up the device even when no exit chain was
        // asked for. With no exit group to point at, the catch-all has to name
        // the tunnel itself -- pointing at a group that was never declared
        // would be a config mihomo rejects.
        let config = render(&RenderPlan {
            tunnel: tunnel(),
            exit_chain: false,
            tun: true,
            ..Default::default()
        });
        assert!(config.contains("- MATCH,aether"), "{config}");
        assert!(!config.contains("proxy-groups"), "no group without a second hop");
        assert!(!config.contains("MATCH,exit"));
    }

    #[test]
    fn a_second_hop_still_takes_the_catch_all_when_both_are_on() {
        let source = source("ours", "https://example.com/a");
        let refs: Vec<&ChainSource> = vec![&source];
        let config = render(&RenderPlan {
            tunnel: tunnel(),
            sources: &refs,
            tun: true,
            ..Default::default()
        });
        assert!(config.contains("- MATCH,exit"), "{config}");
        assert!(config.contains("proxy-groups"));
    }

    #[test]
    fn a_tun_device_that_never_came_up_is_not_reported_as_running() {
        // mihomo answers this with the running state, not the requested one:
        // it keeps serving its mixed port after refusing to make the adapter,
        // so a failed run is otherwise indistinguishable from a good one.
        assert!(!tun_is_enabled(r#"{"tun":{"enable":false,"device":"WhiteAesther"}}"#));
        assert!(tun_is_enabled(r#"{"tun":{"enable":true,"device":"WhiteAesther"}}"#));
        // Nothing to read is not a yes.
        assert!(!tun_is_enabled("{}"));
        assert!(!tun_is_enabled("not json at all"));
        assert!(!tun_is_enabled(r#"{"tun":{}}"#));
    }

    #[test]
    fn iran_bypass_adds_rule_providers_ahead_of_the_exit_group() {
        let config = render(&RenderPlan { tunnel: tunnel(), mixed: 1820, api: 1821, secret: "s", manual: "vless://x", bypass_iran_sites: true, ..Default::default() });
        assert!(config.contains("DOMAIN-SUFFIX,ir,DIRECT"));
        assert!(config.contains("RULE-SET,iran-domain,DIRECT"));
        assert!(config.contains("RULE-SET,iran-ip,DIRECT"));
        // Order matters: a match earlier in the list wins, so the direct
        // rules have to come before the catch-all or they never fire.
        let direct = config.find("RULE-SET,iran-ip,DIRECT").unwrap();
        let catch_all = config.find("MATCH,exit").unwrap();
        assert!(direct < catch_all, "the direct rules must be checked before MATCH");
        assert!(config.contains("behavior: domain"));
        assert!(config.contains("behavior: ipcidr"));
    }

    #[test]
    fn without_the_iran_bypass_no_rule_provider_is_declared() {
        // The default: nothing here should change for someone who never
        // touched the setting.
        let config = render(&RenderPlan { tunnel: tunnel(), mixed: 1820, api: 1821, secret: "s", manual: "vless://x", ..Default::default() });
        assert!(!config.contains("rule-providers"));
        assert!(!config.contains("DOMAIN-SUFFIX,ir"));
        assert_eq!(config.matches("MATCH,exit").count(), 1);
    }

    #[test]
    fn without_a_tunnel_the_nodes_are_reached_directly() {
        // The whole point of the fallback: on a network that resets MASQUE the
        // tunnel never comes up, and a config that still insisted on dialling
        // through it would leave the user with nothing working at all.
        let config = render(&RenderPlan { mixed: 1820, api: 1821, secret: "s", manual: "vless://x", ..Default::default() });
        assert!(!config.contains("dialer-proxy"), "nothing to dial through");
        assert!(
            !config.contains("type: socks5"),
            "a socks5 proxy pointing at a dead port would fail every node it fronted",
        );
        // Everything else must still hold: no direct rule, DNS inside the chain.
        assert!(config.contains("MATCH,exit"));
        assert!(config.contains("enhanced-mode: fake-ip"));
    }

    #[test]
    fn a_cache_for_a_subscription_that_is_gone_is_deleted() {
        let directory = std::env::temp_dir().join(format!("whiteaesther-prune-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let keep = provider_cache("https://example.com/keep");
        for name in [format!("{keep}.yaml"), "0123456789abcdef.yaml".to_string()] {
            std::fs::write(directory.join(name), "proxies: []").unwrap();
        }
        // Pasted configs are not a subscription cache and must survive.
        std::fs::write(directory.join("manual.txt"), "vless://x").unwrap();

        prune_provider_cache(&directory, std::slice::from_ref(&keep));

        assert!(directory.join(format!("{keep}.yaml")).exists());
        assert!(!directory.join("0123456789abcdef.yaml").exists());
        assert!(directory.join("manual.txt").exists());
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn quic_protocols_are_named_as_unusable_behind_the_tunnel() {
        // Measured on a live connection: Cloudflare's connect-ip capsule carries
        // 1306 bytes of inner packet, and a QUIC handshake needs 1308. The node
        // is fine -- the same one answers in under a second dialled directly --
        // so reporting it as unreachable sends people looking for a fault that
        // is not there.
        for kind in ["Hysteria2", "hysteria", "Tuic"] {
            let reason = unusable_behind_the_tunnel(kind).expect("QUIC cannot be carried");
            assert!(reason.contains(kind), "the reason should name the protocol: {reason}");
            assert!(reason.contains("Dial nodes through the tunnel"), "say what to do: {reason}");
        }
    }

    #[test]
    fn a_reality_node_is_found_in_a_base64_subscription() {
        // The shape the user's own panel serves: a base64 block of URIs, the
        // name in the fragment, percent-encoded.
        let body = "vless://id@host:443?security=reality&pbk=x&sid=y#WhiteAesther%20REALITY%20fallback\n\
                    vless://id@host:8080?security=none&type=ws#VLESS-WS";
        let mut found = HashSet::new();
        collect_reality_names(body, &mut found);
        assert!(found.contains("WhiteAesther REALITY fallback"), "{found:?}");
        assert!(!found.contains("VLESS-WS"), "a plain node must not be labelled");
    }

    #[test]
    fn a_reality_node_is_found_in_a_clash_provider() {
        // The other shape: a Clash document, written as flow mappings, which is
        // what a panel serving clash-meta returns.
        let body = "proxies:\n                      - {name: TROJAN-REALITY-A, type: trojan, server: h, port: 8081,                     reality-opts: {public-key: k, short-id: s}}\n                      - {name: plain-trojan, type: trojan, server: h, port: 443}\n";
        let mut found = HashSet::new();
        collect_reality_names(body, &mut found);
        assert!(found.contains("TROJAN-REALITY-A"), "{found:?}");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn a_base64_subscription_is_decoded_and_a_plain_one_is_left_alone() {
        let plain = "vless://id@host:443?security=reality#node";
        // Encoded the way a panel serves it, with the line wrapping they add.
        let encoded = "dmxlc3M6Ly9pZEBob3N0OjQ0Mz9zZWN1cml0eT1yZWFsaXR5I25vZGU=";
        assert_eq!(decode_if_base64(encoded), plain);
        // A file that is already readable must survive untouched, or a Clash
        // document would be turned into rubbish.
        assert_eq!(decode_if_base64(plain), plain);
    }

    #[test]
    fn a_name_with_spaces_and_emoji_survives_the_round_trip() {
        // Node names routinely carry both, and a mangled name matches nothing,
        // which would leave the node silently unlabelled.
        assert_eq!(percent_decode("%F0%9F%87%AF%F0%9F%87%B5%20tokyo"), "\u{1F1EF}\u{1F1F5} tokyo");
        assert_eq!(percent_decode("plain-name"), "plain-name");
        // A stray percent is not an escape and must not eat the next character.
        assert_eq!(percent_decode("100%"), "100%");
    }

    #[test]
    fn quic_is_only_a_problem_on_the_transport_that_cannot_carry_it() {
        // WireGuard has 60 bytes of room the MASQUE path does not, which is the
        // whole difference between a hysteria2 node that works behind the
        // tunnel and one that never completes a handshake.
        let reason = unusable_behind_the_tunnel("Hysteria2").expect("QUIC needs the bigger MTU");
        assert!(reason.contains("WireGuard"), "say which way out there is: {reason}");
    }

    #[test]
    fn everything_that_runs_over_tcp_is_left_alone() {
        for kind in ["Vless", "Trojan", "Vmess", "Shadowsocks", "?"] {
            assert!(unusable_behind_the_tunnel(kind).is_none(), "{kind} works behind the tunnel");
        }
    }

    #[test]
    fn a_secret_differs_between_runs() {
        assert_ne!(secret(), secret());
    }

    #[test]
    fn percent_encoding_covers_the_characters_node_names_actually_use() {
        // Node names arrive from subscriptions and routinely carry spaces and
        // non-ASCII; an unencoded name would build a broken request path.
        assert_eq!(encode("a b"), "a%20b");
        assert_eq!(encode("xhttp-tls -cdn"), "xhttp-tls%20-cdn");
        assert_eq!(encode("safe-._~"), "safe-._~");
        assert!(encode("🇯🇵 tokyo").starts_with('%'));
    }

    #[test]
    fn a_chunked_reply_is_reassembled() {
        // The shape mihomo actually sends a node list in: a hex size, the
        // bytes, then a zero chunk. Before this was read, that size line went
        // to the JSON parser and every node list looked like a crash.
        let wire = "5\r\nhello\r\n2\r\n!!\r\n0\r\n\r\n";
        let mut reader = BufReader::new(wire.as_bytes());
        assert_eq!(read_chunked(&mut reader).unwrap(), "hello!!");
    }

    #[test]
    fn a_chunk_larger_than_we_will_hold_is_refused() {
        let wire = format!("{:x}\r\n", MAX_BODY + 1);
        let mut reader = BufReader::new(wire.as_bytes());
        assert!(read_chunked(&mut reader).is_err());
    }

    #[test]
    fn the_mixed_port_sits_next_to_the_tunnel() {
        // A person configures this one in a browser, so it has to be derivable
        // and the same on the next launch rather than whatever was free.
        assert_eq!(next_port("127.0.0.1:1819".parse().unwrap()), 1820);
        assert_eq!(next_port("127.0.0.1:65535".parse().unwrap()), DEFAULT_MIXED_PORT);
    }

    #[test]
    fn a_taken_port_moves_rather_than_failing() {
        let held = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let taken = held.local_addr().unwrap().port();
        let chosen = preferred_port(taken).unwrap();
        assert_ne!(chosen, taken);
    }
}

#[cfg(test)]
mod config_dump {
    use super::*;

    /// Writes the config the app would generate with the Iran bypass on, so it
    /// can be handed to the real mihomo for validation. Not part of the suite:
    /// it exists to be run by hand when the generated shape changes.
    #[test]
    #[ignore = "writes a config for manual validation against the mihomo binary"]
    fn dump_iran_bypass_config() {
        let out = std::env::var("WHITEAESTHER_CONFIG_DUMP")
            .expect("set WHITEAESTHER_CONFIG_DUMP to the path to write");
        let source = ChainSource {
            name: "ours".into(),
            url: "https://example.com/sub".into(),
            enabled: true,
        };
        let refs: Vec<&ChainSource> = vec![&source];
        let config = render(&RenderPlan {
            tunnel: Some("127.0.0.1:1819".parse().unwrap()),
            mixed: 1820,
            api: 1821,
            secret: "secret",
            sources: &refs,
            bypass_iran_sites: true,
            // Set from the environment so one dump can cover either shape.
            tun: std::env::var("WHITEAESTHER_CONFIG_DUMP_TUN").is_ok(),
            endpoint: std::env::var("WHITEAESTHER_CONFIG_DUMP_ENDPOINT")
                .ok()
                .and_then(|value| value.parse().ok()),
            ..Default::default()
        });
        std::fs::write(&out, config).unwrap();
        println!("wrote {out}");
    }
}
