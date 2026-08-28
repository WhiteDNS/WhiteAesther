use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex, MutexGuard,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use crate::chain::{Chain, ChainRequest, ChainSettings};
use crate::http_bridge::{self, HttpBridge};
use crate::lan_share::{LanDoor, LanSettings, LanStatus};
use crate::system_proxy::{self, ProxyTargets};
use tauri::{AppHandle, Emitter, Manager, State};

const MAX_LOGS: usize = 1_000;
/// A permanently refused identity would otherwise retry forever, which reads on
/// screen as an endless "connecting" and keeps the network busy for nothing.
const MAX_ATTEMPTS: u32 = 8;
/// 3s, 6s, 12s, 24s, 48s, then a minute between attempts.
const BASE_RETRY_SECS: u64 = 3;
const MAX_RETRY_SECS: u64 = 60;
/// Comfortably above a full 1,000-line log with the header, and far below
/// anything that would be a surprise to write to disk.
const MAX_REPORT_BYTES: usize = 1_048_576;
/// Matches the timeout `scripts/stage-core.mjs` already applies to the same `--version` call.
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct CoreProfile {
    pub name: String,
    pub protocol: String,
    pub masque_transport: String,
    pub scan_mode: String,
    pub ip_family: String,
    pub socks_address: String,
    pub quick_reconnect: bool,
    pub validate_secs: u64,
    pub startup_secs: u64,
    pub reconnect_secs: u64,
    pub dns: Vec<String>,
    pub fragment_client_hello: bool,
    pub fragment_size: String,
    pub fragment_delay: String,
    pub data_check: bool,
    pub h2_peer: Option<String>,
    pub ech: Option<String>,
    pub tls_groups: Option<String>,
    pub performance_profile: String,
    pub keepalive_secs: u16,
    pub noize: String,
    pub profile_retry: bool,
    pub log_level: String,
    /// How `peer` is used: "automatic" ignores it, "custom-first" falls back to
    /// discovery once it fails, "custom-only" never falls back.
    pub endpoint_mode: String,
    pub peer: Option<String>,
    pub wg_peer: Option<String>,
    pub core_path: Option<String>,
    pub route_block: String,
    pub route_direct: String,
    pub routes_file: Option<String>,
    /// Capture every application through a TUN device rather than asking them
    /// to follow a proxy.
    ///
    /// The only way to close a DNS leak: a program that speaks to port 53
    /// itself never consults a proxy setting, so no amount of pointing the
    /// system proxy at the tunnel catches it. Needs permission to create a
    /// network adapter, which is why it is not simply always on.
    #[serde(default)]
    pub full_tunnel: bool,
    /// Dial out through a proxy already running on this machine.
    ///
    /// `socks5://host:port` or `http://host:port`, credentials allowed in the
    /// URL. The endpoint sweep, the registration calls and the ECH lookup all
    /// go through it too, so the search does not reveal an address the tunnel
    /// then hides.
    ///
    /// Carried to the engine in the environment rather than on the command
    /// line, because this string can hold a password and a command line is
    /// readable by anything that can list processes.
    #[serde(default)]
    pub upstream_proxy: String,
    /// Read the host name out of the first bytes of a stream, so rules written
    /// as domains match connections made to a bare address.
    ///
    /// On by default in the engine, and what "Iranian sites bypass the tunnel"
    /// leans on whenever a destination arrives without a name.
    #[serde(default = "yes")]
    pub route_sniff: bool,
    /// Register a fresh device when Cloudflare refuses the saved identity.
    ///
    /// On by default in the engine. Off, a refused identity is reported and
    /// kept, which is what someone diagnosing an account wants and what
    /// everyone else would experience as a tunnel that will not come up.
    #[serde(default = "yes")]
    pub auto_reprovision: bool,
    /// Send Iranian sites straight out instead of through the tunnel.
    ///
    /// Filtering only applies to traffic that looks like it left Iran, so a
    /// site already reachable directly gains nothing from the tunnel and only
    /// pays for the exit's bandwidth -- which is otherwise a reason to
    /// disconnect just to get ordinary speed on an ordinary site. The list
    /// this draws on is bundled with the app; see `iran_routes`.
    #[serde(default)]
    pub bypass_iran_sites: bool,
    pub team: Option<String>,
    pub access_client_id: Option<String>,
    pub access_client_secret: Option<String>,
    pub access_email: Option<String>,
    pub access_token: Option<String>,
    pub gateway: bool,
    /// Point the operating system's proxy settings at the SOCKS5 listener while
    /// connected, and put them back on disconnect.
    pub system_proxy: bool,
    /// Keep trying after a route drops. Off, a session that dies is left dead
    /// rather than retried, which is what someone debugging a network wants.
    pub auto_reconnect: bool,
    /// The second hop, and where its nodes come from.
    pub chain: ChainSettings,
    /// Whether other devices on this network may use the tunnel, and on what
    /// terms.
    #[serde(default)]
    pub lan_share: LanSettings,
    /// Leave the system proxy pointed at the dead listener when the tunnel
    /// fails, so applications that follow it fail rather than send the traffic
    /// in the clear.
    ///
    /// The cost is real: until the tunnel comes back or the app is closed, the
    /// machine has no working proxy. Off by default for that reason.
    pub kill_switch: bool,
}

/// `#[serde(default)]` on a bool means false, and both of these default to on
/// in the engine -- so a profile written before they existed has to read as on
/// or upgrading would silently change how traffic is routed.
fn yes() -> bool {
    true
}

impl Default for CoreProfile {
    fn default() -> Self {
        Self {
            name: "Adaptive · Iran".into(),
            protocol: "masque".into(),
            masque_transport: "h2".into(),
            scan_mode: "balanced".into(),
            ip_family: "both".into(),
            socks_address: "127.0.0.1:1819".into(),
            quick_reconnect: true,
            validate_secs: 10,
            startup_secs: 30,
            reconnect_secs: 2,
            dns: vec!["1.1.1.1".into(), "1.0.0.1".into()],
            fragment_client_hello: true,
            fragment_size: "16-32".into(),
            fragment_delay: "2-10".into(),
            data_check: true,
            h2_peer: None,
            ech: None,
            tls_groups: None,
            performance_profile: "auto".into(),
            keepalive_secs: 25,
            auto_reconnect: true,
            chain: ChainSettings::default(),
            lan_share: LanSettings::default(),
            kill_switch: false,
            noize: "balanced".into(),
            profile_retry: true,
            log_level: "info".into(),
            endpoint_mode: "automatic".into(),
            peer: None,
            wg_peer: None,
            core_path: None,
            route_block: String::new(),
            route_direct: String::new(),
            routes_file: None,
            bypass_iran_sites: false,
            full_tunnel: false,
            upstream_proxy: String::new(),
            route_sniff: true,
            auto_reprovision: true,
            team: None,
            access_client_id: None,
            access_client_secret: None,
            access_email: None,
            access_token: None,
            gateway: false,
            system_proxy: false,
        }
    }
}

impl CoreProfile {
    fn validate(&self) -> Result<(), String> {
        require_one_of("protocol", &self.protocol, &["masque", "wg", "gool"])?;
        require_one_of("MASQUE transport", &self.masque_transport, &["h2", "h3"])?;
        require_one_of(
            "scan mode",
            &self.scan_mode,
            &["turbo", "balanced", "thorough", "stealth", "ironclad"],
        )?;
        require_one_of("IP family", &self.ip_family, &["v4", "v6", "both"])?;
        require_one_of(
            "log level",
            &self.log_level,
            &["error", "warn", "info", "debug", "trace"],
        )?;
        require_one_of(
            "Noize profile",
            &self.noize,
            &["off", "light", "firewall", "balanced", "gfw", "aggressive"],
        )?;
        require_one_of(
            "performance profile",
            &self.performance_profile,
            &["auto", "low", "medium", "high"],
        )?;
        require_one_of(
            "endpoint mode",
            &self.endpoint_mode,
            &["automatic", "custom-first", "custom-only"],
        )?;
        if self.endpoint_mode != "automatic" && non_empty(self.peer.as_deref()).is_none() {
            return Err("pinning an endpoint requires a custom address".into());
        }

        self.socks_address
            .parse::<SocketAddr>()
            .map_err(|_| "SOCKS address must be a valid IP:port".to_string())?;
        if !(1..=120).contains(&self.validate_secs) {
            return Err("validation deadline must be between 1 and 120 seconds".into());
        }
        if !(5..=300).contains(&self.startup_secs) {
            return Err("startup deadline must be between 5 and 300 seconds".into());
        }
        if self.reconnect_secs > 120 {
            return Err("reconnect delay must not exceed 120 seconds".into());
        }
        // Zero is allowed and means "say nothing, let the engine choose",
        // which keeps the one default in the engine rather than copying it
        // here to drift. Same contract as the Android client.
        if !(0..=300).contains(&self.keepalive_secs) {
            return Err("WireGuard keepalive must be between 1 and 300 seconds".into());
        }
        if self.dns.is_empty() || self.dns.len() > 8 {
            return Err("one to eight DNS resolvers are required".into());
        }
        for resolver in &self.dns {
            resolver
                .parse::<IpAddr>()
                .map_err(|_| format!("invalid DNS resolver: {resolver}"))?;
        }
        // Minimum is per-field: a fragment size of 0 silently disables the fragmentation the UI
        // still shows as enabled, but a delay of 0 ("no inter-write pause") is legitimate.
        validate_range("fragment size", &self.fragment_size, 1, 1_500)?;
        validate_range("fragment delay", &self.fragment_delay, 0, 10_000)?;
        validate_peer("peer", self.peer.as_deref())?;
        validate_peer("WireGuard peer", self.wg_peer.as_deref())?;
        validate_peer("HTTP/2 peer", self.h2_peer.as_deref())?;
        validate_optional_text("ECH configuration", self.ech.as_deref(), 32_768)?;
        validate_optional_text("TLS groups", self.tls_groups.as_deref(), 4_096)?;
        validate_text("block rules", &self.route_block, 64_000)?;
        validate_text("direct rules", &self.route_direct, 64_000)?;
        validate_optional_text("routes file", self.routes_file.as_deref(), 4_096)?;
        validate_optional_text("team", self.team.as_deref(), 253)?;
        validate_optional_text("Access client ID", self.access_client_id.as_deref(), 4_096)?;
        validate_optional_text(
            "Access client secret",
            self.access_client_secret.as_deref(),
            4_096,
        )?;
        validate_optional_text("Access email", self.access_email.as_deref(), 320)?;
        validate_optional_text("Access token", self.access_token.as_deref(), 32_768)?;
        Ok(())
    }

    /// The log level the child process actually runs at.
    ///
    /// Connection state, the selected edge and the latency are all derived from
    /// info-level core output. Running the child below info suppresses exactly
    /// the lines the supervisor reads, which leaves a perfectly healthy tunnel
    /// showing as "starting" forever. Extra verbosity is passed through, so the
    /// control only ever adds detail.
    fn process_log_level(&self) -> &str {
        match self.log_level.as_str() {
            "debug" | "trace" => self.log_level.as_str(),
            _ => "info",
        }
    }

    fn args(&self, identity_path: &Path) -> Vec<String> {
        let mut args = vec![
            format!("--{}", self.protocol),
            "--scan".into(),
            self.scan_mode.clone(),
            "--ip".into(),
            self.ip_family.clone(),
            "--bind".into(),
            self.socks_address.clone(),
            "--validate-secs".into(),
            self.validate_secs.to_string(),
            "--startup-secs".into(),
            self.startup_secs.to_string(),
            "--reconnect-secs".into(),
            self.reconnect_secs.to_string(),
            "--dns".into(),
            self.dns.join(","),
            "--noize".into(),
            self.noize.clone(),
            "--log-level".into(),
            self.process_log_level().into(),
            "--config".into(),
            identity_path.to_string_lossy().into_owned(),
        ];

        // Left out entirely at zero, which is how the engine is told to keep
        // its own default rather than being handed a copy of it.
        if self.keepalive_secs > 0 {
            args.extend(["--keepalive".into(), self.keepalive_secs.to_string()]);
        }
        if self.protocol == "masque" && self.masque_transport == "h2" {
            args.push("--h2".into());
        }
        if !self.data_check {
            args.push("--no-data-check".into());
        }
        args.push(if self.quick_reconnect {
            "--quick-reconnect".into()
        } else {
            "--no-quick-reconnect".into()
        });
        if self.fragment_client_hello && self.protocol == "masque" && self.masque_transport == "h2"
        {
            args.extend([
                "--fragment".into(),
                "--fragment-size".into(),
                self.fragment_size.clone(),
                "--fragment-delay".into(),
                self.fragment_delay.clone(),
            ]);
        }
        if !self.profile_retry {
            args.push("--no-profile-retry".into());
        }
        // Only when the user asked for it. The address is kept in the profile
        // across a fallback so it is still in the field when they come back to
        // it, and passing it regardless would make the fallback do nothing.
        if self.endpoint_mode != "automatic" {
            if let Some(peer) = non_empty(self.peer.as_deref()) {
                args.extend(["--peer".into(), peer.into()]);
            }
        }
        if let Some(peer) = non_empty(self.wg_peer.as_deref()) {
            args.extend(["--wg-peer".into(), peer.into()]);
        }
        if let Some(peer) = non_empty(self.h2_peer.as_deref()) {
            args.extend(["--h2-peer".into(), peer.into()]);
        }
        if let Some(ech) = non_empty(self.ech.as_deref()).filter(|value| *value != "off") {
            args.extend(["--ech".into(), ech.into()]);
        }
        if let Some(groups) = non_empty(self.tls_groups.as_deref()) {
            args.extend(["--tls-groups".into(), groups.into()]);
        }
        if self.performance_profile != "auto" {
            args.extend(["--perf".into(), self.performance_profile.clone()]);
        }
        if !self.route_block.trim().is_empty() {
            args.extend(["--route-block".into(), self.route_block.clone()]);
        }
        if !self.route_direct.trim().is_empty() {
            args.extend(["--route-direct".into(), self.route_direct.clone()]);
        }
        if let Some(path) = non_empty(self.routes_file.as_deref()) {
            args.extend(["--routes".into(), path.into()]);
        }
        if self.gateway {
            args.push("--gateway".into());
        }
        args
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreSnapshot {
    pub state: String,
    pub pid: Option<u32>,
    pub core_path: Option<String>,
    pub version: Option<String>,
    pub transport: Option<String>,
    pub endpoint: Option<String>,
    pub socks_address: String,
    pub latency_ms: Option<f64>,
    pub started_at: Option<u64>,
    pub last_error: Option<String>,
    /// What the supervisor is doing right now, in the user's words. Carries the
    /// retry countdown, so a slow recovery is visibly progress rather than a stall.
    pub status_message: Option<String>,
    /// 0 while the first launch is in flight, then the retry number.
    pub attempt: u32,
    pub max_attempts: u32,
    /// The kill switch is holding traffic: the tunnel is down, the system proxy
    /// still points at it, and the supervisor is retrying in the background.
    pub blocking: bool,
}

impl Default for CoreSnapshot {
    fn default() -> Self {
        Self {
            state: "idle".into(),
            pid: None,
            core_path: None,
            version: None,
            transport: None,
            endpoint: None,
            socks_address: "127.0.0.1:1819".into(),
            latency_ms: None,
            started_at: None,
            last_error: None,
            status_message: None,
            attempt: 0,
            max_attempts: MAX_ATTEMPTS,
            blocking: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreLogEvent {
    pub timestamp: u64,
    pub stream: String,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreProbe {
    pub available: bool,
    pub path: Option<String>,
    pub version: Option<String>,
    pub message: String,
}

/// One connection the user asked for, across however many process launches it
/// takes. The profile is the one they configured, before any per-attempt
/// transport substitution, so retries never compound.
struct Session {
    generation: u64,
    profile: CoreProfile,
    attempt: u32,
}

/// The route the operating system proxy is actually using.
///
/// A boolean cannot distinguish the tunnel from the second hop. That made a
/// later request to move the machine from WARP to the chain look idempotent and
/// get ignored, even though it was a different route with a different exit IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyRoute {
    Tunnel(SocketAddr),
    Chain(SocketAddr),
}

struct SupervisorInner {
    child: Mutex<Option<Child>>,
    snapshot: Mutex<CoreSnapshot>,
    logs: Mutex<VecDeque<CoreLogEvent>>,
    session: Mutex<Option<Session>>,
    /// Bumped by every start and every stop. A retry thread that wakes up on a
    /// stale generation has been superseded and does nothing.
    generation: AtomicU64,
    /// The listener the system proxy is currently pointed at.
    ///
    /// Held across an apply so two live UI commands cannot race and leave the
    /// registry describing one route while the supervisor remembers another.
    proxy_route: Mutex<Option<ProxyRoute>>,
    /// A reporting run of the core -- a scan or an endpoint test. Separate from
    /// `child` because it is short-lived and independently cancellable.
    scan_child: Mutex<Option<Child>>,
    /// The local HTTP proxy the system proxy points at. Only alive while the
    /// system proxy is applied, and dropped with it.
    bridge: Mutex<Option<HttpBridge>>,
    /// Log lines waiting to be handed to the window.
    ///
    /// The thread reading the core's stdout is the only thing draining a 64KB
    /// pipe: if it stops to emit an IPC message per line, a busy window becomes
    /// backpressure and the core blocks mid-scan on its own logging. Nothing on
    /// the reading side may wait on the interface, so lines land here and a
    /// separate pump delivers them.
    pending: Mutex<Vec<CoreLogEvent>>,
    /// Set when the snapshot has changed since the pump last sent it.
    snapshot_dirty: AtomicBool,
}

impl SupervisorInner {
    fn is_current(&self, generation: u64) -> bool {
        self.generation.load(Ordering::SeqCst) == generation
    }
}

#[derive(Clone)]
pub struct CoreSupervisor {
    inner: Arc<SupervisorInner>,
}

impl CoreSupervisor {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(SupervisorInner {
                child: Mutex::new(None),
                snapshot: Mutex::new(CoreSnapshot::default()),
                logs: Mutex::new(VecDeque::with_capacity(MAX_LOGS)),
                session: Mutex::new(None),
                generation: AtomicU64::new(0),
                proxy_route: Mutex::new(None),
                scan_child: Mutex::new(None),
                bridge: Mutex::new(None),
                pending: Mutex::new(Vec::new()),
                snapshot_dirty: AtomicBool::new(false),
            }),
        }
    }

    /// The listener to measure through, or `None` when nothing is connected.
    ///
    /// Deliberately narrow: the latency probe needs one string and no more, and
    /// handing it the whole snapshot would let it read state it has no business
    /// acting on.
    pub fn connected_socks(&self) -> Option<String> {
        let snapshot = lock(&self.inner.snapshot);
        (snapshot.state == "connected").then(|| snapshot.socks_address.clone())
    }

    /// The gateway the tunnel is connected to, as an address.
    ///
    /// Full tunnel needs it: with the default route pointing into the TUN
    /// device, the tunnel's own packets to this address would be captured and
    /// handed back to the tunnel that produced them.
    pub fn endpoint_address(&self) -> Option<IpAddr> {
        let snapshot = lock(&self.inner.snapshot);
        snapshot
            .endpoint
            .as_deref()?
            .parse::<SocketAddr>()
            .ok()
            .map(|address| address.ip())
    }

    /// Whether the first hop can carry a QUIC handshake.
    ///
    /// MASQUE cannot and WireGuard can, and the difference is 28 bytes: see
    /// [`crate::chain::unusable_behind_the_tunnel`]. Reported rather than
    /// worked out in the chain, because only the supervisor knows which
    /// transport actually came up -- a profile set to MASQUE can fall back.
    pub fn carries_quic(&self) -> bool {
        let snapshot = lock(&self.inner.snapshot);
        !matches!(snapshot.transport.as_deref(), Some("masque-h2") | Some("masque-h3"))
    }

    /// Records a line from something the app runs alongside the core.
    ///
    /// The chain uses this for mihomo's output. Anything with a piped stream
    /// must have it drained by somebody, or the process blocks on its own
    /// logging once the pipe fills -- and its diagnosis is lost either way.
    pub fn record(&self, stream: &str, level: &str, message: String) {
        push_log(&self.inner, stream, level, message);
    }

    /// Refuses when a connection is live: a scan competes with it for the same
    /// gateways and would report worse numbers than the network really offers.
    pub fn require_idle(&self, message: &str) -> Result<(), String> {
        let state = lock(&self.inner.snapshot).state.clone();
        if state == "idle" || state == "stopped" || state == "error" {
            Ok(())
        } else {
            Err(message.to_string())
        }
    }

    pub fn hold_scan(&self, child: Child) -> Result<(), String> {
        let mut guard = lock(&self.inner.scan_child);
        if guard.is_some() {
            return Err("a scan is already running".into());
        }
        *guard = Some(child);
        Ok(())
    }

    pub fn poll_scan(&self) -> crate::scanner::ScanState {
        let mut guard = lock(&self.inner.scan_child);
        let Some(child) = guard.as_mut() else {
            return crate::scanner::ScanState::Gone;
        };
        match child.try_wait() {
            Ok(Some(_)) => {
                guard.take();
                crate::scanner::ScanState::Exited
            }
            Ok(None) => crate::scanner::ScanState::Running,
            Err(_) => {
                guard.take();
                crate::scanner::ScanState::Exited
            }
        }
    }

    pub fn cancel_scan(&self) -> bool {
        let Some(mut child) = lock(&self.inner.scan_child).take() else {
            return false;
        };
        let _ = child.kill();
        let _ = child.wait();
        true
    }

    pub fn shutdown(&self, app: &AppHandle) {
        self.cancel_scan();
        let _ = stop_inner(&self.inner, app);
    }
}

#[tauri::command]
pub fn runtime_info() -> serde_json::Value {
    serde_json::json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    })
}

/// Runs `body` on the blocking pool and reports a joining failure through the
/// same error channel the body itself uses.
async fn off_thread<T, F>(what: &str, body: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    match tauri::async_runtime::spawn_blocking(body).await {
        Ok(result) => result,
        Err(error) => Err(format!("{what} did not finish: {error}")),
    }
}

#[tauri::command]
pub async fn probe_core(app: AppHandle, profile: Option<CoreProfile>) -> CoreProbe {
    // Spawns `aether --version` and waits for it. On the main thread that is a
    // frozen window, and it runs before every connect.
    off_thread("the core check", move || Ok(probe_core_blocking(&app, profile)))
        .await
        .unwrap_or_else(|error| CoreProbe {
            available: false,
            path: None,
            version: None,
            message: error,
        })
}

fn probe_core_blocking(app: &AppHandle, profile: Option<CoreProfile>) -> CoreProbe {
    let requested = profile.and_then(|value| value.core_path);
    match resolve_core_path(app, requested.as_deref()) {
        Ok(path) => match core_version(&path) {
            Ok(version) => CoreProbe {
                available: true,
                path: Some(path.to_string_lossy().into_owned()),
                version: Some(version.clone()),
                message: format!("{version} is ready"),
            },
            Err(error) => CoreProbe {
                available: false,
                path: Some(path.to_string_lossy().into_owned()),
                version: None,
                message: error,
            },
        },
        Err(error) => CoreProbe {
            available: false,
            path: None,
            version: None,
            message: error,
        },
    }
}

#[tauri::command]
pub async fn start_core(
    app: AppHandle,
    supervisor: State<'_, CoreSupervisor>,
    profile: CoreProfile,
) -> Result<CoreSnapshot, String> {
    let inner = supervisor.inner.clone();
    off_thread("starting the core", move || start_core_blocking(&app, &inner, profile)).await
}

fn start_core_blocking(
    app: &AppHandle,
    inner: &Arc<SupervisorInner>,
    profile: CoreProfile,
) -> Result<CoreSnapshot, String> {
    profile.validate()?;
    // A session waiting out a retry delay has no live child, so checking the
    // child alone would let a second connection start underneath the first.
    if lock(&inner.child).is_some() || lock(&inner.session).is_some() {
        return Err("Aether core is already running".into());
    }

    let generation = inner.generation.fetch_add(1, Ordering::SeqCst) + 1;
    *lock(&inner.session) = Some(Session {
        generation,
        profile: profile.clone(),
        attempt: 0,
    });

    match launch(app, inner, &profile, 0, generation) {
        Ok(()) => Ok(lock(&inner.snapshot).clone()),
        Err(error) => {
            *lock(&inner.session) = None;
            Err(error)
        }
    }
}

/// Starts one Aether process for `profile` and wires its output back.
///
/// `profile` is the profile for this attempt, which is not necessarily the one
/// the user configured -- see [`profile_for_attempt`].
fn launch(
    app: &AppHandle,
    inner: &Arc<SupervisorInner>,
    profile: &CoreProfile,
    attempt: u32,
    generation: u64,
) -> Result<(), String> {
    let core_path = resolve_core_path(app, profile.core_path.as_deref())?;
    let version = core_version(&core_path)?;
    let config_dir = app
        .path()
        .app_config_dir()
        .map_err(|error| format!("cannot resolve app config directory: {error}"))?;
    let identity_dir = config_dir.join("identity");
    std::fs::create_dir_all(&identity_dir)
        .map_err(|error| format!("cannot create identity directory: {error}"))?;
    let identity_path = identity_dir.join("aether.toml");

    // The bundled Iran list and the user's own routes file both become one
    // `--routes` argument: Aether reads only one such path, so having each
    // land in a different place would mean the two features quietly overwrite
    // each other rather than combining, and whichever the user set second
    // would win with no sign the other stopped applying.
    let mut effective_profile = profile.clone();
    if profile.bypass_iran_sites {
        let generated = config_dir.join("routing").join("generated-routes.txt");
        crate::iran_routes::write_combined_routes_file(
            &generated,
            profile.routes_file.as_deref().map(Path::new),
        )?;
        effective_profile.routes_file = Some(generated.to_string_lossy().into_owned());
    }

    let mut command = Command::new(&core_path);
    command
        .args(effective_profile.args(&identity_path))
        .current_dir(&config_dir)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    set_optional_env(&mut command, "AETHER_TEAM", profile.team.as_deref());
    set_optional_env(
        &mut command,
        "AETHER_ACCESS_CLIENT_ID",
        profile.access_client_id.as_deref(),
    );
    set_optional_env(
        &mut command,
        "AETHER_ACCESS_CLIENT_SECRET",
        profile.access_client_secret.as_deref(),
    );
    set_optional_env(
        &mut command,
        "AETHER_ACCESS_EMAIL",
        profile.access_email.as_deref(),
    );
    set_optional_env(
        &mut command,
        "AETHER_ACCESS_TOKEN",
        profile.access_token.as_deref(),
    );

    // In the environment rather than on the command line: this one can carry a
    // password in the URL, and a command line is readable by anything that can
    // list processes.
    set_optional_env(
        &mut command,
        "AETHER_UPSTREAM",
        non_empty(Some(profile.upstream_proxy.as_str())),
    );

    // Both of these are on in the engine and are switched off by the literal
    // "0", so the variable is worth setting only to turn one off. Leaving it
    // unset keeps the single default where it belongs -- in the engine --
    // instead of copying it here where the two could drift apart.
    if !profile.route_sniff {
        command.env("AETHER_ROUTE_SNIFF", "0");
    }
    if !profile.auto_reprovision {
        command.env("AETHER_REPROVISION", "0");
    }

    hide_console_window(&mut command);

    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to start Aether core: {error}"))?;
    let pid = child.id();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    {
        // A stop that landed while this process was being spawned has nothing to
        // kill yet, so claim the slot and re-check under the same lock the stop
        // takes. Otherwise the child outlives the session and runs unsupervised.
        let mut guard = lock(&inner.child);
        if !inner.is_current(generation) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(());
        }
        *guard = Some(child);
    }

    {
        let mut snapshot = lock(&inner.snapshot);
        *snapshot = CoreSnapshot {
            state: "starting".into(),
            pid: Some(pid),
            core_path: Some(core_path.to_string_lossy().into_owned()),
            version: Some(version),
            transport: Some(transport_label(profile).into()),
            endpoint: None,
            socks_address: profile.socks_address.clone(),
            latency_ms: None,
            started_at: Some(now_millis()),
            last_error: None,
            status_message: (attempt > 0).then(|| {
                format!(
                    "Attempt {attempt} of {MAX_ATTEMPTS} on {}",
                    transport_name(profile)
                )
            }),
            attempt,
            max_attempts: MAX_ATTEMPTS,
            blocking: false,
        };
        mark_snapshot_dirty(inner);
    }
    supervisor_log(inner, "info", session_summary(profile, attempt));

    if let Some(stdout) = stdout {
        spawn_log_reader(app.clone(), inner.clone(), stdout, "stdout");
    }
    if let Some(stderr) = stderr {
        spawn_log_reader(app.clone(), inner.clone(), stderr, "stderr");
    }
    spawn_exit_monitor(app.clone(), inner.clone(), generation);
    spawn_route_watch(app.clone(), inner.clone(), generation);

    Ok(())
}

#[tauri::command]
pub async fn stop_core(
    app: AppHandle,
    supervisor: State<'_, CoreSupervisor>,
) -> Result<CoreSnapshot, String> {
    let inner = supervisor.inner.clone();
    off_thread("stopping the core", move || {
        stop_inner(&inner, &app)?;
        Ok(lock(&inner.snapshot).clone())
    })
    .await
}

/// Applies or removes the system proxy while a connection is already up.
///
/// Without this, choosing "whole machine" after connecting only changed a field
/// in the profile: the proxy was applied on the log line that reports the
/// listener, which had already gone by. The screen offers the choice while
/// connected, so it has to mean something then.
#[tauri::command]
pub fn set_system_proxy(
    app: AppHandle,
    supervisor: State<'_, CoreSupervisor>,
    chain: State<'_, Chain>,
    enabled: bool,
) -> Result<bool, String> {
    let inner = &supervisor.inner;

    // Remember it for the rest of the session, so a reconnect keeps the choice.
    if let Some(session) = lock(&inner.session).as_mut() {
        session.profile.system_proxy = enabled;
    }

    if !enabled {
        clear_system_proxy(&app, inner);
        return Ok(false);
    }

    let (state, socks) = {
        let snapshot = lock(&inner.snapshot);
        (snapshot.state.clone(), snapshot.socks_address.clone())
    };
    let chain_requested = chain_is_in_play(
        chain.is_running(),
        lock(&inner.session)
            .as_ref()
            .is_some_and(|session| session.profile.chain.enabled),
    );
    // Before the listener exists there is nothing to point at; the connect path
    // applies it when the core reports itself up.
    if state != "connected" {
        return Ok(false);
    }
    let tunnel_address = socks.parse::<SocketAddr>().ok();
    if let Some(route) = desired_proxy_route(chain_requested, chain.address(), tunnel_address) {
        apply_proxy_route(&app, inner, route);
    } else if chain_requested {
        // The core reports connected before mihomo has necessarily loaded its
        // providers. Pointing the machine at WARP in that window is the race
        // that made Whole machine keep the wrong exit after the chain became
        // ready. The connection log path applies the final route once startup
        // succeeds or records the chain failure before falling back.
        supervisor_log(
            inner,
            "info",
            "system proxy is waiting for the requested chain to become ready".into(),
        );
        return Ok(false);
    } else {
        // Log the parse failure with the same diagnostic used by the startup
        // path. A valid connected snapshot always has an address, but silently
        // doing nothing here would make corrupted state needlessly opaque.
        let _ = tunnel_proxy_route(&socks, inner);
    }
    Ok(proxy_is_applied(inner))
}

/// Opens or closes the door other devices on this network come in through.
///
/// Deliberately separate from the system proxy: that decides how far the tunnel
/// reaches on *this* machine, and this decides whether it reaches off it at
/// all. Sharing without credentials is allowed, because a household network
/// where that is fine is the common case -- but it is the caller's job to have
/// said so plainly first, and [`LanStatus::open`] carries it back so the screen
/// can keep saying it.
#[tauri::command]
pub fn set_lan_share(
    supervisor: State<'_, CoreSupervisor>,
    chain: State<'_, Chain>,
    door: State<'_, LanDoor>,
    settings: LanSettings,
) -> Result<LanStatus, String> {
    let inner = &supervisor.inner;

    // Remembered for the rest of the session, so a reconnect keeps the choice.
    if let Some(session) = lock(&inner.session).as_mut() {
        session.profile.lan_share = settings.clone();
    }

    if !settings.enabled {
        door.close();
        supervisor_log(inner, "info", "network sharing stopped".into());
        return Ok(LanStatus::stopped());
    }

    let carrier = carrier_address(inner, &chain).ok_or(
        "connect first: there is nothing to share until the tunnel is carrying traffic",
    )?;
    let status = door.open(carrier, &settings)?;
    supervisor_log(
        inner,
        "info",
        match (&status.address, status.open) {
            (Some(address), true) => format!(
                "network sharing open on {address} with no sign-in; anyone on this network can use it"
            ),
            (Some(address), false) => format!("network sharing open on {address}, sign-in required"),
            (None, _) => "network sharing open".into(),
        },
    );
    Ok(status)
}

#[tauri::command]
pub fn lan_share_status(door: State<'_, LanDoor>) -> LanStatus {
    door.status()
}

/// The listener traffic is actually leaving through: the second hop when one is
/// running, the tunnel when it is not, and nothing at all when disconnected.
fn carrier_address(inner: &SupervisorInner, chain: &Chain) -> Option<SocketAddr> {
    if let Some(address) = chain.address() {
        return Some(address);
    }
    let snapshot = lock(&inner.snapshot);
    if snapshot.state != "connected" {
        return None;
    }
    snapshot.socks_address.parse().ok()
}

/// Whether a full-tunnel wish can actually be carried out right now.
///
/// The wish lives in the profile and outlives any one launch, so it is
/// routinely on in a copy that has no permission to honour it -- after a
/// restart that was never elevated, or an update, or simply the next morning.
/// That must cost the person nothing: the engine still starts, the exit chain
/// still runs, and only the device is left out. Reporting the refusal as a
/// failure of the whole chain is what turned a missing permission into a
/// connection that would not come up at all.
fn tun_is_possible(inner: &SupervisorInner, wanted: bool) -> bool {
    if !wanted {
        return false;
    }
    if crate::elevation::is_elevated() {
        return true;
    }
    supervisor_log(
        inner,
        "warn",
        "full tunnel is switched on but this copy cannot create a network device; \
         running without it. Switch Full tunnel on again to be offered a restart."
            .into(),
    );
    false
}

/// Returned by [`set_full_tunnel`] when the device cannot be created without
/// more permission than this process has. Matched by the screen, so it is a
/// constant rather than a sentence someone might reword.
pub const NEEDS_ADMINISTRATOR: &str = "needs-administrator";

/// Whether this copy was restarted to finish switching full tunnel on.
///
/// The screen uses it to reconnect by itself, so the restart looks like the app
/// carrying on rather than like something the person has to redo.
#[tauri::command]
pub fn resuming_full_tunnel() -> bool {
    crate::elevation::started_to_resume_full_tunnel()
}

/// Whether full tunnel can be started without asking for anything first.
///
/// Read by the screen before it offers the switch, so the choice can say what
/// it will cost rather than failing after the fact.
#[tauri::command]
pub fn full_tunnel_is_permitted() -> bool {
    crate::elevation::is_elevated()
}

/// Restarts the app with the permission a network device needs, and ends this
/// copy once the new one is on its way.
///
/// Everything the session held is rebuilt on the other side: the profile is on
/// disk, and the elevated copy is told to switch full tunnel on once it has
/// connected. Nothing is torn down until the prompt has actually been accepted,
/// so refusing it leaves a working connection exactly as it was.
#[tauri::command]
pub fn restart_as_administrator(app: AppHandle, supervisor: State<'_, CoreSupervisor>) -> Result<(), String> {
    crate::elevation::relaunch_elevated()?;
    // Only now: the tunnel and the proxy have to be put back before this
    // process goes, or the machine is left pointing at listeners that are
    // about to disappear.
    supervisor.shutdown(&app);
    app.exit(0);
    Ok(())
}

/// Turns full tunnel on or off on a connection that is already up.
///
/// Separate from [`set_system_proxy`] because they are different mechanisms
/// with different failure modes, even though the screen offers them as one
/// choice: the system proxy is a setting other programs may consult, and this
/// is a network device they cannot avoid.
#[tauri::command]
pub async fn set_full_tunnel(
    app: AppHandle,
    supervisor: State<'_, CoreSupervisor>,
    chain: State<'_, Chain>,
    enabled: bool,
) -> Result<bool, String> {
    let inner = &supervisor.inner;

    let settings = {
        let mut guard = lock(&inner.session);
        match guard.as_mut() {
            Some(session) => {
                session.profile.full_tunnel = enabled;
                Some((session.profile.chain.clone(), session.profile.bypass_iran_sites))
            }
            None => None,
        }
    };
    // Nothing is running, so there is nothing to rebuild; the choice is
    // remembered in the profile and applied at the next connect.
    let Some((chain_settings, bypass_iran_sites)) = settings else {
        return Ok(false);
    };

    // Refused before anything is torn down, and named precisely: the screen
    // turns this one into an offer to restart rather than an error, so it has
    // to be distinguishable from a device that failed for any other reason.
    if enabled && !crate::elevation::is_elevated() {
        return Err(NEEDS_ADMINISTRATOR.into());
    }

    let Some(socks) = supervisor.connected_socks() else {
        return Ok(false);
    };
    let tunnel = socks
        .parse::<SocketAddr>()
        .map_err(|_| format!("the proxy address {socks} cannot be parsed"))?;

    if !enabled && !chain_settings.enabled {
        // The engine was only running to hold the device up.
        chain.stop();
        supervisor_log(inner, "info", "full tunnel stopped".into());
        return Ok(false);
    }

    let address = chain.start(
        &app,
        &ChainRequest {
            tunnel: Some(tunnel),
            settings: &chain_settings,
            bypass_iran_sites,
            tun: enabled,
            endpoint: supervisor.endpoint_address(),
        },
    )?;
    supervisor_log(
        inner,
        "info",
        match enabled {
            true => format!("full tunnel is up; every application is captured, listener on {address}"),
            false => format!("full tunnel stopped; listener on {address}"),
        },
    );
    // Whatever is pointed at the old listener has to follow the new one.
    app.state::<LanDoor>().retarget(address);
    if lock(&inner.session)
        .as_ref()
        .is_some_and(|session| session.profile.system_proxy)
    {
        apply_proxy_route(&app, inner, ProxyRoute::Chain(address));
    }
    Ok(enabled)
}

/// Turns the chain on or off on a connection that is already up.
///
/// Without this the switch only took effect at the next connect, which is the
/// same fault the system proxy toggle had: the screen offers the choice while
/// connected, so it has to mean something then. Changing a subscription goes
/// through here too, because mihomo reads its sources at startup and would
/// otherwise keep serving the old list.
#[tauri::command]
pub async fn set_chain(
    app: AppHandle,
    supervisor: State<'_, CoreSupervisor>,
    chain: State<'_, Chain>,
    settings: ChainSettings,
) -> Result<bool, String> {
    let inner = &supervisor.inner;

    // Remember it for the rest of the session, so a reconnect keeps the choice.
    // Read alongside the write rather than a second lock, so nothing else
    // changes it in between.
    let (bypass_iran_sites, full_tunnel) = {
        let mut guard = lock(&inner.session);
        match guard.as_mut() {
            Some(session) => {
                session.profile.chain = settings.clone();
                (session.profile.bypass_iran_sites, session.profile.full_tunnel)
            }
            None => (false, false),
        }
    };

    let socks = supervisor.connected_socks();
    let tunnel = match socks.as_deref() {
        Some(address) => Some(
            address
                .parse::<SocketAddr>()
                .map_err(|_| format!("the proxy address {address} cannot be parsed"))?,
        ),
        None => None,
    };
    // Without a tunnel the chain can still carry traffic straight to the nodes.
    // Refusing outright is what left this unusable on a network that resets
    // MASQUE: the tunnel never came up, so the chain never ran, so nothing the
    // user configured did anything at all.
    if tunnel.is_none() && (!settings.enabled || settings.through_tunnel) {
        chain.stop();
        return Ok(false);
    }

    // The engine also runs to hold up a full-tunnel device, so "is a second hop
    // wanted" is no longer the same question as "should it be running".
    let tun = tun_is_possible(inner, full_tunnel);
    let started = if settings.enabled || tun {
        let address = chain.start(
            &app,
            &ChainRequest {
                tunnel,
                settings: &settings,
                bypass_iran_sites,
                tun,
                endpoint: supervisor.endpoint_address(),
            },
        )?;
        supervisor_log(
            inner,
            "info",
            format!("chain listening on {address}; every node dials through the tunnel"),
        );
        Some(address)
    } else {
        chain.stop();
        None
    };

    // Anything pointed at the old listener would go around the change the user
    // just made -- devices on the network included, which is why the shared
    // door is retargeted rather than left to be reconfigured by hand.
    if let Some(carrier) = started.or_else(|| tunnel) {
        app.state::<LanDoor>().retarget(carrier);
    }

    // The proxy has to follow whichever listener is now carrying traffic.
    // Leaving it pointed at the old one would send everything around the change
    // the user just made.
    // Read the current intent after chain startup, which can take several
    // seconds. Whether a proxy happened to be applied before this command is
    // not the contract: Whole machine may deliberately be waiting for this
    // very chain to become ready.
    let session = lock(&inner.session);
    if session
        .as_ref()
        .is_some_and(|session| session.profile.system_proxy)
    {
        match (started, socks.as_deref()) {
            (Some(address), _) => apply_proxy_route(&app, inner, ProxyRoute::Chain(address)),
            (None, Some(address)) => {
                if let Some(route) = tunnel_proxy_route(address, inner) {
                    apply_proxy_route(&app, inner, route);
                }
            }
            (None, None) => {}
        }
    }
    Ok(started.is_some())
}

#[tauri::command]
pub fn core_status(supervisor: State<'_, CoreSupervisor>) -> CoreSnapshot {
    lock(&supervisor.inner.snapshot).clone()
}

#[tauri::command]
pub fn core_logs(supervisor: State<'_, CoreSupervisor>) -> Vec<CoreLogEvent> {
    lock(&supervisor.inner.logs).iter().cloned().collect()
}

#[tauri::command]
pub async fn save_profile(app: AppHandle, profile: CoreProfile) -> Result<CoreProfile, String> {
    off_thread("saving the profile", move || save_profile_blocking(app, profile)).await
}

fn save_profile_blocking(app: AppHandle, profile: CoreProfile) -> Result<CoreProfile, String> {
    profile.validate()?;
    let mut stored = profile.clone();
    stored.access_client_secret = None;
    stored.access_token = None;
    let path = profile_path(&app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create profile directory: {error}"))?;
    }
    let bytes = serde_json::to_vec_pretty(&stored)
        .map_err(|error| format!("cannot serialize profile: {error}"))?;
    std::fs::write(&path, bytes).map_err(|error| format!("cannot save profile: {error}"))?;
    Ok(profile)
}

#[tauri::command]
pub async fn load_profile(app: AppHandle) -> Result<CoreProfile, String> {
    off_thread("loading the profile", move || load_profile_blocking(app)).await
}

fn load_profile_blocking(app: AppHandle) -> Result<CoreProfile, String> {
    let path = profile_path(&app)?;
    if !path.exists() {
        return Ok(CoreProfile::default());
    }
    let bytes = std::fs::read(&path).map_err(|error| format!("cannot read profile: {error}"))?;
    let mut stored: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("profile is invalid: {error}"))?;
    migrate_endpoint_mode(&mut stored);
    migrate_keepalive(&mut stored);
    let profile: CoreProfile =
        serde_json::from_value(stored).map_err(|error| format!("profile is invalid: {error}"))?;
    profile.validate()?;
    Ok(profile)
}

/// Moves a profile off the old keepalive default.
///
/// The client used to send 5 seconds and every saved profile carries that
/// number, whether or not anyone chose it -- so leaving them alone would mean
/// only fresh installs got the new interval, and the two clients would sit five
/// seconds apart forever. 5 was never a choice anyone made on purpose here, and
/// it is five times noisier on the wire than it needs to be.
///
/// Only the exact old default moves. Any other number was typed by someone, and
/// overriding that would be a worse trade than the one this fixes.
fn migrate_keepalive(stored: &mut serde_json::Value) {
    const OLD_DEFAULT: u64 = 5;
    let Some(object) = stored.as_object_mut() else {
        return;
    };
    if object.get("keepaliveSecs").and_then(serde_json::Value::as_u64) == Some(OLD_DEFAULT) {
        object.insert("keepaliveSecs".into(), serde_json::json!(25));
    }
}

/// Keeps a profile saved before endpoint modes existed behaving as it did.
///
/// Back then any address in `peer` was passed to the core unconditionally, so a
/// profile carrying one was pinned whether or not it said so. Defaulting those
/// to "automatic" would quietly stop honouring an address the user had set.
fn migrate_endpoint_mode(stored: &mut serde_json::Value) {
    let Some(object) = stored.as_object_mut() else {
        return;
    };
    if object.contains_key("endpointMode") {
        return;
    }
    let pinned = object
        .get("peer")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|peer| !peer.trim().is_empty());
    if pinned {
        object.insert("endpointMode".into(), "custom-only".into());
    }
}

/// Writes a diagnostics report the user has already reviewed to disk.
///
/// The contents are composed and redacted in the UI and shown verbatim before
/// this is ever called -- nothing is gathered here, and nothing is sent
/// anywhere. The name is supplied by the caller so the timestamp carries the
/// user's locale, which is why it is sanitised rather than trusted.
#[tauri::command]
pub async fn save_report(
    app: AppHandle,
    contents: String,
    filename: String,
) -> Result<String, String> {
    off_thread("saving the report", move || {
        save_report_blocking(&app, contents, filename)
    })
    .await
}

fn save_report_blocking(
    app: &AppHandle,
    contents: String,
    filename: String,
) -> Result<String, String> {
    if contents.trim().is_empty() {
        return Err("the report is empty".into());
    }
    if contents.len() > MAX_REPORT_BYTES {
        return Err("the report is too large to save".into());
    }
    let name = sanitize_report_name(&filename)?;
    let directory = app
        .path()
        .app_config_dir()
        .map_err(|error| format!("cannot resolve app config directory: {error}"))?
        .join("reports");
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create the reports directory: {error}"))?;
    let path = directory.join(name);
    std::fs::write(&path, contents).map_err(|error| format!("cannot save the report: {error}"))?;
    Ok(path.to_string_lossy().into_owned())
}

/// Reduces a caller-supplied name to a plain file name in the reports
/// directory. Anything that could climb out of it is rejected rather than
/// rewritten, so a surprising name fails loudly instead of writing somewhere
/// unexpected.
fn sanitize_report_name(filename: &str) -> Result<String, String> {
    let name = filename.trim();
    if name.is_empty() || name.len() > 128 {
        return Err("the report file name is invalid".into());
    }
    if !name.ends_with(".txt") {
        return Err("reports are saved as .txt".into());
    }
    if name.starts_with('.')
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err("the report file name is invalid".into());
    }
    Ok(name.to_string())
}

/// The core executable, the directory it runs in, and the identity file it
/// uses. Shared so a scan provisions the same identity a connection would,
/// rather than a second one.
pub fn core_paths(
    app: &AppHandle,
    profile: &CoreProfile,
) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let core_path = resolve_core_path(app, profile.core_path.as_deref())?;
    let config_dir = app
        .path()
        .app_config_dir()
        .map_err(|error| format!("cannot resolve app config directory: {error}"))?;
    let identity_dir = config_dir.join("identity");
    std::fs::create_dir_all(&identity_dir)
        .map_err(|error| format!("cannot create identity directory: {error}"))?;
    Ok((core_path, config_dir, identity_dir.join("aether.toml")))
}

pub fn hide_console(command: &mut Command) {
    hide_console_window(command);
}

fn spawn_log_reader<R: Read + Send + 'static>(
    app: AppHandle,
    inner: Arc<SupervisorInner>,
    reader: R,
    stream: &'static str,
) {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(line) => record_log(&app, &inner, stream, line),
                // Skip an undecodable line, do not end the stream. map_while(Result::ok) stopped
                // the whole reader on the first non-UTF-8 byte, which silently froze every piece
                // of state this stream feeds — including the only path out of "connected".
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => continue,
                Err(_) => break,
            }
        }
    });
}

/// How long a round trip has to take before the route counts as unusable.
///
/// A good edge answers in about a tenth of a second from here; a degraded one
/// was measured at three to ten. Two seconds is far outside ordinary variance
/// and still well inside "the page has not loaded yet".
const BAD_ROUTE_MS: f64 = 2_000.0;

/// Consecutive bad samples before acting, at [`ROUTE_WATCH`] apart.
///
/// Three rather than one: a single slow probe is a hiccup, and reconnecting on
/// every hiccup would be worse than the problem.
const BAD_ROUTE_STREAK: u32 = 3;
const ROUTE_WATCH: Duration = Duration::from_secs(10);

/// Watches the route a live tunnel is actually giving, and re-scans when it is
/// no longer worth having.
///
/// The engine caches the gateway that last worked and reuses it on the next
/// connect, checking only that it still answers a handshake -- not that it is
/// still fast. A Cloudflare edge that degrades therefore stays pinned for good,
/// because every successful connect writes it back to the cache. Measured on
/// one machine, one minute apart: the cached edge took 3 to 10 seconds to first
/// byte and then timed out, while a freshly scanned one took 0.11 seconds.
///
/// Nothing in the app noticed, because a handshake through a congested tunnel is
/// still quick -- so the status chart read healthy while no page would load.
fn spawn_route_watch(app: AppHandle, inner: Arc<SupervisorInner>, generation: u64) {
    thread::spawn(move || {
        let mut streak = 0u32;
        loop {
            thread::sleep(ROUTE_WATCH);
            if !inner.is_current(generation) {
                return;
            }
            let (state, socks) = {
                let snapshot = lock(&inner.snapshot);
                (snapshot.state.clone(), snapshot.socks_address.clone())
            };
            // Only a live tunnel has a route to judge. Connecting and retrying
            // are already someone else's problem.
            if state != "connected" {
                streak = 0;
                continue;
            }
            let Ok(address) = socks.parse::<SocketAddr>() else {
                return;
            };
            match crate::latency::round_trip_ms(address) {
                Some(ms) if ms < BAD_ROUTE_MS => streak = 0,
                _ => streak += 1,
            }
            if streak < BAD_ROUTE_STREAK {
                continue;
            }
            if !inner.is_current(generation) {
                return;
            }
            rescan_bad_route(&app, &inner, generation);
            return;
        }
    });
}

/// Reconnects without the cached gateway, keeping everything else as it was.
///
/// The transport is deliberately left alone. Alternating H2 and H3 is the answer
/// to a transport that cannot get through at all; here it plainly can, and the
/// edge behind it is what went bad -- moving a working transport to one this
/// network may block would trade a slow tunnel for no tunnel.
///
/// The retry budget is untouched for the same reason: this is not a failed
/// attempt, it is a good connection being replaced with a better one.
fn rescan_bad_route(app: &AppHandle, inner: &Arc<SupervisorInner>, generation: u64) {
    let profile = {
        let mut guard = lock(&inner.session);
        let Some(session) = guard.as_mut() else {
            return;
        };
        if session.generation != generation {
            return;
        }
        // For the rest of this session. A cache that has already served one bad
        // gateway has not earned another chance before the next launch.
        session.profile.quick_reconnect = false;
        session.attempt = 0;
        session.profile.clone()
    };

    supervisor_log(
        inner,
        "warn",
        format!(
            "this gateway has been slower than {}ms for {} checks in a row; searching for a \n             better one rather than staying on it",
            BAD_ROUTE_MS as u64, BAD_ROUTE_STREAK
        ),
    );

    // Same shape as an explicit reconnect: invalidate, stop, start. Bumping the
    // generation first stops the old child's monitors from treating the kill
    // below as a crash and racing this with a retry of their own.
    let next = inner.generation.fetch_add(1, Ordering::SeqCst) + 1;
    app.state::<Chain>().stop();
    if let Some(child) = lock(&inner.child).take().as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    // The proxy is re-applied when the new tunnel reports itself up; leaving it
    // pointed at the old one would strand traffic in the gap.
    clear_system_proxy(app, inner);

    *lock(&inner.session) = Some(Session { generation: next, profile: profile.clone(), attempt: 0 });
    {
        let mut snapshot = lock(&inner.snapshot);
        snapshot.state = "reconnecting".into();
        snapshot.pid = None;
        snapshot.status_message = Some("Finding a faster gateway".into());
        mark_snapshot_dirty(inner);
    }
    if let Err(error) = launch(app, inner, &profile, 0, next) {
        handle_exit(app, inner, next, error);
    }
}

fn spawn_exit_monitor(app: AppHandle, inner: Arc<SupervisorInner>, generation: u64) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(350));
        if !inner.is_current(generation) {
            return;
        }
        let exit = {
            let mut guard = lock(&inner.child);
            // Taken by a stop, or by a newer session. Either way this process is
            // no longer the one being supervised.
            let Some(child) = guard.as_mut() else {
                return;
            };
            match child.try_wait() {
                Ok(Some(status)) => {
                    guard.take();
                    Some(Ok(status))
                }
                Ok(None) => None,
                Err(error) => {
                    guard.take();
                    Some(Err(error.to_string()))
                }
            }
        };

        let Some(exit) = exit else { continue };
        let reason = match exit {
            Ok(status) if status.success() => "The Aether core exited".to_string(),
            Ok(status) => format!("The Aether core exited with {status}"),
            Err(error) => format!("Cannot monitor the Aether core: {error}"),
        };
        handle_exit(&app, &inner, generation, reason);
        return;
    });
}

#[derive(Debug)]
enum ExitDecision {
    Retry { attempt: u32, profile: CoreProfile },
    GiveUp { profile: CoreProfile },
    /// Out of retries, but the kill switch is holding traffic. Ending the
    /// session here would strand the machine behind a proxy nothing is
    /// listening on, so the budget resets and the search keeps going.
    Hold { profile: CoreProfile },
    /// The exit belongs to a session that has been superseded or stopped.
    Ignore,
}

/// Advances the session's retry count and says what should happen next.
///
/// Clearing a spent session has to be conditional on it still being *this*
/// session: a stop and a fresh start can both land between a core exiting and
/// this running, and unconditionally clearing would throw away the new
/// session's retry budget while leaving it connected.
fn decide_exit(session: &mut Option<Session>, generation: u64, holding: bool) -> ExitDecision {
    let Some(current) = session.as_mut() else {
        return ExitDecision::Ignore;
    };
    if current.generation != generation {
        return ExitDecision::Ignore;
    }
    current.attempt += 1;
    let attempt = current.attempt;
    let profile = current.profile.clone();
    // Asked not to retry, the first death is the last one. Without this the
    // supervisor spends eight attempts and several minutes on a network the
    // person watching has already decided is not going to work.
    if attempt > MAX_ATTEMPTS || !profile.auto_reconnect {
        // Unless traffic is being held. A kill switch that stops trying is a
        // trap: it blocks the machine and then waits to be noticed. Reset the
        // budget and keep searching on a slow loop instead, so the block lifts
        // itself the moment a route comes back.
        if holding {
            current.attempt = 0;
            return ExitDecision::Hold { profile };
        }
        *session = None;
        return ExitDecision::GiveUp { profile };
    }
    ExitDecision::Retry { attempt, profile }
}

fn give_up(
    app: &AppHandle,
    inner: &Arc<SupervisorInner>,
    generation: u64,
    profile: &CoreProfile,
    reason: String,
) {
    // Every attempt went to the same pinned address, so naming it is more use
    // than repeating the core's last error.
    let summary = if !profile.auto_reconnect {
        format!("{reason}. Not retried, because \"keep me connected\" is off.")
    } else if profile.endpoint_mode == "custom-only" {
        format!(
            "The pinned endpoint {} never answered. Stopped after {MAX_ATTEMPTS} attempts — switch \
             Endpoint back to Automatic to search instead.",
            profile.peer.as_deref().unwrap_or("(unset)")
        )
    } else {
        format!("{reason}. Stopped after {MAX_ATTEMPTS} attempts.")
    };
    {
        let mut snapshot = lock(&inner.snapshot);
        // A stop bumps the generation before it takes this lock, so a stale
        // generation here means the idle snapshot is the newer truth.
        if !inner.is_current(generation) {
            return;
        }
        snapshot.state = "error".into();
        snapshot.pid = None;
        snapshot.status_message = None;
        snapshot.attempt = 0;
        snapshot.last_error = Some(summary);
        mark_snapshot_dirty(inner);
    }
    supervisor_log(
        inner,
        "error",
        format!("gave up after {MAX_ATTEMPTS} attempts: {reason}"),
    );
    app.state::<Chain>().stop();

    // The kill switch only bites here, on the failure path. An explicit stop and
    // a quit both restore unconditionally, so the machine can always be put back
    // by disconnecting or closing the app — and a kill rather than a close is
    // caught by the recovery pass at the next launch.
    if profile.kill_switch && proxy_is_applied(inner) {
        supervisor_log(
            inner,
            "warn",
            "the tunnel is down and the system proxy has been left pointing at it, so traffic \
             fails instead of leaving in the clear. Disconnect to put it back."
                .into(),
        );
        return;
    }
    clear_system_proxy(app, inner);
}

/// Decides what happens after a core process ends without the user asking.
///
/// Retries on a widening delay and eventually stops, rather than either giving
/// up on the first failure -- which is what a hostile network produces -- or
/// retrying a dead configuration forever.
fn handle_exit(app: &AppHandle, inner: &Arc<SupervisorInner>, generation: u64, reason: String) {
    // Bound to its own statement so the session lock is released before
    // anything below reaches for another one.
    // Read before taking the session lock, so the decision and the proxy state
    // cannot be taken from two different moments.
    let holding = {
        let session = lock(&inner.session);
        session.as_ref().is_some_and(|current| current.profile.kill_switch)
            && proxy_is_applied(inner)
    };
    let decision = decide_exit(&mut lock(&inner.session), generation, holding);
    let (attempt, base_profile) = match decision {
        ExitDecision::Ignore => return,
        ExitDecision::GiveUp { profile } => return give_up(app, inner, generation, &profile, reason),
        ExitDecision::Hold { profile } => return hold(app, inner, generation, profile, reason),
        ExitDecision::Retry { attempt, profile } => (attempt, profile),
    };

    // The tunnel this proxy points at is gone, and the bridge in front of it
    // answers nothing. Left applied through the backoff and the next attempt,
    // it takes the whole machine off the network for as long as the retry runs
    // -- the browser fails, and the failure reads as "the app broke everything"
    // rather than "one attempt did not come up".
    //
    // The kill switch is the one case where holding it is the point, and that
    // path is `hold` below; an ordinary retry has to leave the machine usable.
    if !base_profile.kill_switch {
        clear_system_proxy(app, inner);
    }

    let profile = profile_for_attempt(&base_profile, attempt);
    let delay = retry_delay(attempt);
    // A pinned address that quietly stops being used is the one substitution a
    // user has to be told about -- otherwise the connection they are looking at
    // is not the one they asked for.
    let fell_back = fell_back_to_discovery(&base_profile, &profile);
    {
        let mut snapshot = lock(&inner.snapshot);
        if !inner.is_current(generation) {
            return;
        }
        snapshot.state = "reconnecting".into();
        snapshot.pid = None;
        snapshot.attempt = attempt;
        snapshot.status_message = Some(if fell_back {
            format!(
                "The pinned endpoint failed · searching for a working one · retry {attempt} of \
                 {MAX_ATTEMPTS} on {} in {}s",
                transport_name(&profile),
                delay.as_secs()
            )
        } else {
            format!(
                "{reason} · retry {attempt} of {MAX_ATTEMPTS} on {} in {}s",
                transport_name(&profile),
                delay.as_secs()
            )
        });
        mark_snapshot_dirty(inner);
    }
    if fell_back {
        supervisor_log(
            inner,
            "warn",
            format!(
                "custom endpoint {} failed; falling back to automatic discovery",
                base_profile.peer.as_deref().unwrap_or("(unset)")
            ),
        );
    }
    supervisor_log(
        inner,
        "warn",
        format!(
            "{reason}; retry {attempt} of {MAX_ATTEMPTS} on {} in {}s",
            transport_label(&profile),
            delay.as_secs()
        ),
    );

    let app = app.clone();
    let inner = inner.clone();
    thread::spawn(move || {
        // Woken in slices so a stop during a minute-long backoff is felt at once
        // rather than after the full delay.
        let deadline = Instant::now() + delay;
        while Instant::now() < deadline {
            if !inner.is_current(generation) {
                return;
            }
            thread::sleep(Duration::from_millis(250));
        }
        if !inner.is_current(generation) {
            return;
        }
        if let Err(error) = launch(&app, &inner, &profile, attempt, generation) {
            handle_exit(&app, &inner, generation, error);
        }
    });
}

/// How long to wait between attempts while traffic is being held.
///
/// Slower than the ordinary backoff on purpose: nothing is getting through, so
/// there is no rush, and hammering a hostile network is what gets an address
/// blocked rather than unblocked.
const HOLD_RETRY: Duration = Duration::from_secs(30);

/// Keeps the block in place and keeps looking for a way out.
///
/// The session survives, so the machine is never left behind a proxy with
/// nothing behind it and nothing trying to fix that.
fn hold(
    app: &AppHandle,
    inner: &Arc<SupervisorInner>,
    generation: u64,
    profile: CoreProfile,
    reason: String,
) {
    {
        let mut snapshot = lock(&inner.snapshot);
        if !inner.is_current(generation) {
            return;
        }
        snapshot.state = "error".into();
        snapshot.pid = None;
        snapshot.attempt = 0;
        snapshot.blocking = true;
        snapshot.status_message = Some(format!(
            "Traffic is blocked while the tunnel is down · trying again every {}s",
            HOLD_RETRY.as_secs()
        ));
        snapshot.last_error = Some(format!(
            "{reason}. Traffic is being held rather than sent in the clear — the search continues \
             in the background, or disconnect to put your system proxy back."
        ));
        mark_snapshot_dirty(inner);
    }
    supervisor_log(
        inner,
        "warn",
        format!("{reason}; holding traffic and retrying every {}s", HOLD_RETRY.as_secs()),
    );

    let app = app.clone();
    let inner = inner.clone();
    thread::spawn(move || {
        let deadline = Instant::now() + HOLD_RETRY;
        while Instant::now() < deadline {
            if !inner.is_current(generation) {
                return;
            }
            thread::sleep(Duration::from_millis(250));
        }
        if !inner.is_current(generation) {
            return;
        }
        // Attempt 1 rather than 0: the alternation in profile_for_attempt is what
        // gets a blocked transport past a filter, and a hold that only ever tried
        // the configured one would sit there forever.
        let next = profile_for_attempt(&profile, 1);
        if let Err(error) = launch(&app, &inner, &next, 1, generation) {
            handle_exit(&app, &inner, generation, error);
        }
    });
}

/// The profile to launch for a given retry.
///
/// The core takes one transport and never falls back between them. H3 rides
/// QUIC, and a network that blocks UDP kills it outright -- so retrying the same
/// dead transport eight times is eight guaranteed failures. Alternate instead.
///
/// The *first* retry switches. A retry now follows a complete fruitless sweep,
/// which is two minutes of evidence that this transport is not getting through
/// right now; spending another two minutes proving it again is the single
/// slowest thing this supervisor could do. Only MASQUE has a second transport
/// to alternate to.
fn profile_for_attempt(base: &CoreProfile, attempt: u32) -> CoreProfile {
    let mut profile = base.clone();
    if attempt > 0 && base.protocol == "masque" && attempt % 2 == 1 {
        profile.masque_transport = if base.masque_transport == "h2" {
            "h3".into()
        } else {
            "h2".into()
        };
    }
    // "Custom first" means exactly one go at the pinned address. Retrying it
    // eight times is what the mode exists to avoid -- if it were reachable the
    // first attempt would have worked.
    if attempt > 0 && base.endpoint_mode == "custom-first" {
        profile.endpoint_mode = "automatic".into();
    }
    profile
}

/// Whether this attempt gave up on the pinned address the previous one used.
fn fell_back_to_discovery(base: &CoreProfile, attempted: &CoreProfile) -> bool {
    base.endpoint_mode == "custom-first" && attempted.endpoint_mode == "automatic"
}

fn retry_delay(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(5);
    Duration::from_secs((BASE_RETRY_SECS << shift).min(MAX_RETRY_SECS))
}

fn push_log(inner: &SupervisorInner, stream: &str, level: &str, message: String) {
    let event = CoreLogEvent {
        timestamp: now_millis(),
        stream: stream.into(),
        level: level.into(),
        message,
    };
    {
        let mut logs = lock(&inner.logs);
        if logs.len() == MAX_LOGS {
            logs.pop_front();
        }
        logs.push_back(event.clone());
    }
    // Buffered, not emitted. The pump below delivers these in batches.
    let mut pending = lock(&inner.pending);
    if pending.len() < MAX_LOGS {
        pending.push(event);
    }
}

/// What the supervisor itself did, as opposed to what the core printed.
///
/// Retries, give-ups and the configuration a session ran with leave no trace in
/// the core's own output, so without these a diagnostics report cannot answer
/// the question it was collected for.
fn supervisor_log(inner: &SupervisorInner, level: &str, message: String) {
    push_log(inner, "supervisor", level, message);
}

fn record_log(app: &AppHandle, inner: &SupervisorInner, stream: &str, message: String) {
    let message = message.trim().to_string();
    push_log(inner, stream, log_level(&message), message.clone());

    let connected = {
        let mut snapshot = lock(&inner.snapshot);
        // Once the core is gone, buffered lines still draining from the pipe must
        // not resurrect a live-looking state. pid is the terminal marker -- both
        // stop_inner and the exit monitor clear it -- so one guard covers the stop
        // path and the crash path together. Lines still reach the Diagnostics
        // stream above; they just stop driving security state.
        if snapshot.pid.is_none() {
            false
        } else {
            let before = snapshot.clone();
            apply_log_to_snapshot(&message, &mut snapshot);
            let connected = snapshot.state == "connected";
            if connected {
                snapshot.attempt = 0;
                snapshot.status_message = None;
            }
            // Most log lines change nothing. Emitting regardless meant two IPC
            // messages and a full re-render for every line the core printed.
            if *snapshot != before {
                mark_snapshot_dirty(inner);
            }
            connected
        }
    };
    // The core hunts, fails, and hunts again on its own, forever, without ever
    // exiting. Every retry this supervisor has -- the attempt count, the widening
    // backoff, the H2/H3 alternation, the give-up screen -- hangs off the process
    // exiting, so none of it ever ran: the app sat on "Searching" repeating the
    // same sweep on the same transport until someone gave up watching.
    //
    // Take the decision back. One fruitless sweep is enough to know this
    // transport is not getting through right now, and trying the other one is
    // worth more than a second identical pass.
    if !connected && sweep_exhausted(&message) {
        end_fruitless_sweep(inner);
    }

    // A tunnel that came up has spent its failures. Anything after this is a
    // fresh problem and gets the full retry budget again. Kept out of the
    // snapshot lock above so the two are never held at once.
    if connected {
        let (wanted, chain_settings, lan, bypass_iran_sites, full_tunnel) = {
            let mut guard = lock(&inner.session);
            match guard.as_mut() {
                Some(session) => {
                    session.attempt = 0;
                    (
                        session.profile.system_proxy,
                        session.profile.chain.clone(),
                        session.profile.lan_share.clone(),
                        session.profile.bypass_iran_sites,
                        session.profile.full_tunnel,
                    )
                }
                None => (
                    false,
                    ChainSettings::default(),
                    LanSettings::default(),
                    false,
                    false,
                ),
            }
        };

        let socks = lock(&inner.snapshot).socks_address.clone();

        // The chain comes up before the proxy is pointed anywhere, because the
        // whole question of *where* to point it is answered by whether the
        // chain is carrying traffic. Starting them the other way round would
        // aim the machine at the tunnel for as long as mihomo took to load a
        // subscription -- traffic leaving with the wrong exit address, at the
        // exact moment the user believes the opposite.
        // `connected` is true for every line the core prints once the tunnel is
        // up, not just the one that brought it up -- so this ran again on each
        // of them, and every run tore down a working chain to build another.
        // The log showed two starts a second apart, on different ports, leaving
        // the screen watching a listener that had already been replaced.
        let chain = app.state::<Chain>();
        // Full tunnel needs the engine running whether or not a second hop was
        // asked for, because the device it holds up is the engine's.
        let full_tunnel = tun_is_possible(inner, full_tunnel);
        let engine_wanted = chain_settings.enabled || full_tunnel;
        let carrier = if engine_wanted && !chain.is_running() {
            let endpoint = lock(&inner.snapshot)
                .endpoint
                .as_deref()
                .and_then(|value| value.parse::<SocketAddr>().ok())
                .map(|address| address.ip());
            match socks.parse::<SocketAddr>() {
                Ok(tunnel) => match chain.start(
                    app,
                    &ChainRequest {
                        tunnel: Some(tunnel),
                        settings: &chain_settings,
                        bypass_iran_sites,
                        tun: full_tunnel,
                        endpoint,
                    },
                ) {
                    Ok(address) => {
                        supervisor_log(
                            inner,
                            "info",
                            format!("chain listening on {address}; every node dials through the tunnel"),
                        );
                        Some(address)
                    }
                    Err(error) => {
                        // Say which hop failed. "No route" would be a lie: the
                        // tunnel is up and it is the second hop that did not.
                        supervisor_log(
                            inner,
                            "error",
                            format!("the tunnel is up but the chain did not start: {error}"),
                        );
                        None
                    }
                },
                Err(_) => None,
            }
        } else {
            None
        };

        // Whether or not this machine's own proxy is being pointed anywhere,
        // a device on the network that was already sharing must not be left
        // aimed at the listener from the previous session.
        if let Some(address) = carrier.or_else(|| chain.address()).or_else(|| socks.parse().ok()) {
            let door = app.state::<LanDoor>();
            door.retarget(address);
            // Reconnecting, or starting the app with sharing already switched
            // on, has to put the door back. Leaving it to the screen would mean
            // the setting only took effect if someone opened that panel.
            if lan.enabled && !door.status().running {
                match door.open(address, &lan) {
                    Ok(status) => supervisor_log(
                        inner,
                        "info",
                        match (&status.address, status.open) {
                            (Some(at), true) => format!(
                                "network sharing open on {at} with no sign-in; anyone on this network can use it"
                            ),
                            (Some(at), false) => format!("network sharing open on {at}, sign-in required"),
                            (None, _) => "network sharing open".into(),
                        },
                    ),
                    Err(error) => {
                        supervisor_log(inner, "warn", format!("could not share on this network: {error}"))
                    }
                }
            }
        }

        if wanted {
            match carrier.or_else(|| chain.address()) {
                // mihomo's mixed listener speaks HTTP itself, so it is what the
                // system proxy points at and the bridge is not needed at all.
                Some(address) => apply_proxy_route(app, inner, ProxyRoute::Chain(address)),
                None => {
                    // Reaching this branch means chain startup definitively
                    // failed (rather than merely still being in progress), so
                    // retain the established fallback to the live tunnel. The
                    // failure immediately above remains visible in diagnostics.
                    if let Some(route) = tunnel_proxy_route(&socks, inner) {
                        apply_proxy_route(app, inner, route);
                    }
                }
            }
        }
    }
}

/// Parses the core listener into the route used when no second hop is active.
fn tunnel_proxy_route(socks: &str, inner: &SupervisorInner) -> Option<ProxyRoute> {
    match socks.parse::<SocketAddr>() {
        Ok(address) => Some(ProxyRoute::Tunnel(address)),
        Err(_) => {
            supervisor_log(
                inner,
                "warn",
                format!("cannot use {socks} as a system proxy address"),
            );
            None
        }
    }
}

/// Whether a second hop is what traffic should be following right now.
///
/// A chain that is already listening settles this on its own, whatever the
/// profile says. Asking the profile alone let the two disagree, and when they
/// did, "this app only" named the chain's listener while "whole machine"
/// pointed the machine at WARP -- one browser, two exit addresses, decided by a
/// switch that is supposed to change how far the tunnel reaches and not where
/// it comes out.
fn chain_is_in_play(chain_running: bool, chain_enabled: bool) -> bool {
    chain_running || chain_enabled
}

/// Chooses the route for a live Whole machine request.
///
/// A requested chain with no address means "wait", not "use the tunnel". This
/// distinction closes the startup race while leaving an ordinary connection
/// free to use WARP directly.
fn desired_proxy_route(
    chain_requested: bool,
    chain_address: Option<SocketAddr>,
    tunnel_address: Option<SocketAddr>,
) -> Option<ProxyRoute> {
    if chain_requested {
        chain_address.map(ProxyRoute::Chain)
    } else {
        tunnel_address.map(ProxyRoute::Tunnel)
    }
}

fn proxy_is_applied(inner: &SupervisorInner) -> bool {
    lock(&inner.proxy_route).is_some()
}

fn proxy_route_needs_update(current: Option<ProxyRoute>, requested: ProxyRoute) -> bool {
    current != Some(requested)
}

/// Points the OS at exactly `route`, retargeting an already-applied proxy when
/// the carrier changes.
///
/// [`system_proxy::apply`] preserves the original backup after its first call,
/// so a WARP -> chain transition can be written in place. The replacement HTTP
/// bridge is prepared first and the old one is dropped only after the registry
/// accepts the new target, leaving no window where the selected listener is
/// absent.
fn apply_proxy_route(app: &AppHandle, inner: &SupervisorInner, route: ProxyRoute) {
    let mut current = lock(&inner.proxy_route);
    if !proxy_route_needs_update(*current, route) {
        return;
    }

    let (targets, next_bridge) = match route {
        ProxyRoute::Chain(address) => (
            ProxyTargets {
                socks: address,
                http: address,
            },
            None,
        ),
        ProxyRoute::Tunnel(address) => {
            // Windows follows an HTTP proxy and effectively ignores a SOCKS
            // one, so the bridge translates WinINET traffic into SOCKS5. Other
            // platforms use `targets.socks` and simply ignore the bridge.
            let bridge = match http_bridge::start(address) {
                Ok(bridge) => bridge,
                Err(error) => {
                    supervisor_log(
                        inner,
                        "warn",
                        format!("could not start the local HTTP proxy: {error}"),
                    );
                    return;
                }
            };
            let targets = ProxyTargets { socks: address, http: bridge.address() };
            (targets, Some(bridge))
        }
    };

    match system_proxy::apply(app, targets) {
        Ok(()) => {
            // Replace only after the OS points at `targets`; until this line an
            // old tunnel bridge may still be serving the previous route.
            *lock(&inner.bridge) = next_bridge;
            *current = Some(route);
            supervisor_log(
                inner,
                "info",
                match route {
                    ProxyRoute::Chain(address) => {
                        format!("system proxy set to the chain at {address}")
                    }
                    ProxyRoute::Tunnel(address) => {
                        format!("system proxy set to {address} via {}", targets.http)
                    }
                },
            );
        }
        Err(error) => {
            // `next_bridge` drops here. The previous route and bridge stay
            // intact because the OS rejected the replacement.
            supervisor_log(
                inner,
                "warn",
                format!("could not set the system proxy: {error}"),
            )
        }
    }
}

/// Puts the OS proxy back, whatever else is going on.
///
/// Called on every path that ends a session -- stop, give-up and quit -- because
/// a proxy left pointing at a listener that no longer exists takes the machine
/// off the network.
fn clear_system_proxy(app: &AppHandle, inner: &SupervisorInner) {
    // The user explicitly asked to put the machine back, so the blocking state
    // is cleared even if the platform restore later reports an error. The route
    // itself remains recorded on failure so another cleanup can retry it.
    {
        let mut snapshot = lock(&inner.snapshot);
        if snapshot.blocking {
            snapshot.blocking = false;
            mark_snapshot_dirty(inner);
        }
    }
    let mut route = lock(&inner.proxy_route);
    if route.is_none() {
        return;
    }
    match system_proxy::revert(app) {
        Ok(()) => {
            // Keep the bridge alive until after the OS no longer points at it.
            lock(&inner.bridge).take();
            *route = None;
            supervisor_log(inner, "info", "system proxy restored".into());
        }
        Err(error) => {
            // Keep both the route and its bridge so a later cleanup can retry
            // and existing proxy-aware traffic is not aimed at a dead port.
            supervisor_log(
                inner,
                "error",
                format!("could not restore the system proxy: {error}"),
            )
        }
    }
}

/// Whether the core has just announced that a whole sweep found nothing and it
/// intends to run the same one again.
///
/// Matched on the core's own words, which is a contract made of prose and will
/// need revisiting if the wording changes -- the same caveat that already
/// applies to every other line read here. Both phrasings are required to appear
/// together in practice; either alone is enough to act on.
fn sweep_exhausted(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    lowered.contains("rescanning shortly")
        || lowered.contains("no usable masque gateway found")
        || lowered.contains("scan deadline reached with no gateway")
}

/// Ends a session whose sweep came back empty, so the supervisor's own retry
/// runs instead of the core quietly repeating itself.
///
/// Killing the child is the whole mechanism: the exit monitor sees it go, and
/// `handle_exit` applies the attempt count, the backoff and the transport
/// alternation that were already written and never previously reachable from
/// this state.
fn end_fruitless_sweep(inner: &SupervisorInner) {
    let mut guard = lock(&inner.child);
    let Some(child) = guard.as_mut() else {
        return;
    };
    // Already gone, or on its way: the exit monitor owns it from here.
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    let _ = child.kill();
    drop(guard);
    supervisor_log(
        inner,
        "warn",
        "a full sweep found no gateway; trying the other transport rather than repeating it".into(),
    );
}

fn apply_log_to_snapshot(message: &str, snapshot: &mut CoreSnapshot) {
    if message.contains("hunting for a working") || message.contains("verifying cached") {
        snapshot.state = "scanning".into();
    }
    if message.contains("MASQUE transport: HTTP/2") {
        snapshot.transport = Some("masque-h2".into());
        snapshot.state = "connecting".into();
    } else if message.contains("MASQUE transport: HTTP/3") {
        snapshot.transport = Some("masque-h3".into());
        snapshot.state = "connecting".into();
    } else if message.contains("validating WireGuard tunnel") {
        snapshot.transport = Some("wireguard".into());
        snapshot.state = "connecting".into();
    }
    if let Some(endpoint) = parse_endpoint(message) {
        snapshot.endpoint = Some(endpoint);
    }
    if let Some(latency) = parse_latency_ms(message) {
        snapshot.latency_ms = Some(latency);
    }
    // Three guards so a bind FAILURE cannot read as a success: no failure wording on the line;
    // the address comes from the gate we actually matched (a bare "listening on " picked up a
    // different listener earlier in the line); and it must parse, as parse_endpoint already requires.
    // Errs toward not-connected, which is the safe direction for this indicator.
    // ponytail: matching prose is the wrong contract. Ceiling is the core emitting structured
    // events, or probing the SOCKS port here before believing it is up.
    const LISTEN_GATES: [&str; 2] = ["socks5 server listening on ", "socks5 listening on "];
    const FAILURE_MARKERS: [&str; 7] = [
        "failed", "could not", "cannot", "unable to", "refused", "already in use", "error",
    ];
    let lowered = message.to_ascii_lowercase();
    if !FAILURE_MARKERS.iter().any(|marker| lowered.contains(marker)) {
        for gate in LISTEN_GATES {
            let Some(rest) = message.split(gate).nth(1) else {
                continue;
            };
            if let Some(candidate) = rest.split_whitespace().next() {
                if candidate.parse::<SocketAddr>().is_ok() {
                    snapshot.socks_address = candidate.to_string();
                    snapshot.state = "connected".into();
                    // A route is up, so nothing is being held any more.
                    snapshot.blocking = false;
                }
            }
            break;
        }
    }
    if message.contains("reconnecting") {
        snapshot.state = "reconnecting".into();
    }
    // An error and a reconnect are orthogonal: excluding "reconnecting" here hid the most
    // common phrasing for a failed retry ("... FAILED, reconnecting") from every UI surface.
    if message.contains(" ERROR ") || message.starts_with("ERROR") {
        snapshot.last_error = Some(strip_logger_prefix(message));
    }
}

fn parse_endpoint(message: &str) -> Option<String> {
    const MARKERS: [&str; 5] = [
        "selected MASQUE gateway ",
        "selected WireGuard endpoint ",
        "using cloudflare edge ",
        "cached gateway ",
        "cached endpoint ",
    ];
    for marker in MARKERS {
        let Some(rest) = message.split(marker).nth(1) else {
            continue;
        };
        let candidate = rest
            .split_whitespace()
            .next()?
            .trim_end_matches(|c| c == ',' || c == ')');
        if candidate.parse::<SocketAddr>().is_ok() {
            return Some(candidate.into());
        }
    }
    None
}

fn parse_latency_ms(message: &str) -> Option<f64> {
    let rest = message.split("rtt ").nth(1)?;
    let token = rest
        .split_whitespace()
        .next()?
        .trim_end_matches(|c| c == ')' || c == ',');
    if let Some(value) = token.strip_suffix("ms") {
        return value.parse().ok();
    }
    if let Some(value) = token.strip_suffix('s') {
        return value.parse::<f64>().ok().map(|seconds| seconds * 1_000.0);
    }
    None
}

fn stop_inner(inner: &SupervisorInner, app: &AppHandle) -> Result<(), String> {
    // The chain exists only to carry a live tunnel's traffic; without one it
    // would sit there dialling a SOCKS port nothing is answering on. The same
    // is true of the door other devices come in through: left open over a dead
    // tunnel it is a machine on the network that accepts connections and then
    // fails every one of them.
    app.state::<Chain>().stop();
    app.state::<LanDoor>().close();
    // Invalidate first. A retry sleeping out its backoff has no child to kill,
    // and would otherwise launch a process after the user asked it to stop.
    inner.generation.fetch_add(1, Ordering::SeqCst);
    *lock(&inner.session) = None;
    clear_system_proxy(app, inner);

    let mut child = lock(&inner.child).take();
    if let Some(child) = child.as_mut() {
        child
            .kill()
            .map_err(|error| format!("failed to stop Aether core: {error}"))?;
        let _ = child.wait();
    }
    let mut snapshot = lock(&inner.snapshot);
    snapshot.state = "idle".into();
    snapshot.pid = None;
    snapshot.transport = None;
    snapshot.endpoint = None;
    snapshot.latency_ms = None;
    snapshot.started_at = None;
    snapshot.last_error = None;
    snapshot.status_message = None;
    snapshot.attempt = 0;
    mark_snapshot_dirty(inner);
    Ok(())
}

fn resolve_core_path(app: &AppHandle, requested: Option<&str>) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    if let Some(path) = non_empty(requested) {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(path) = std::env::var("WHITEAESTHER_CORE_PATH") {
        if !path.trim().is_empty() {
            candidates.push(PathBuf::from(path));
        }
    }
    if let Ok(resource_dir) = app.path().resource_dir() {
        candidates.push(resource_dir.join(core_filename()));
        candidates.push(resource_dir.join("binaries").join(core_filename()));
    }
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            candidates.push(parent.join(core_filename()));
        }
    }
    if let Ok(current_dir) = std::env::current_dir() {
        candidates.push(current_dir.join(core_filename()));
        candidates.push(
            current_dir
                .join("..")
                .join("Aether")
                .join("aether")
                .join("target")
                .join("debug")
                .join(core_filename()),
        );
    }

    for candidate in candidates {
        if !candidate.is_file() {
            continue;
        }
        // Skip a candidate we cannot resolve rather than abandoning the search: `?` here let one
        // unusable entry (a path unlinked between is_file and canonicalize) deny core discovery
        // entirely, even though a perfectly good sidecar sat later in the list.
        let Ok(canonical) = candidate.canonicalize() else {
            continue;
        };
        let filename = canonical
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if filename == "aether" || filename.starts_with("aether-") {
            return Ok(canonical);
        }
    }
    Err("Aether core was not found. Choose the aether executable in Preferences or set WHITEAESTHER_CORE_PATH.".into())
}

fn core_version(path: &Path) -> Result<String, String> {
    // The deadline has to cover the READ, not just the child's exit. `.output()` waited for EOF
    // on the pipes, so a core that forked a grandchild inheriting stdout hung here forever — and
    // this runs from probe_core on every launch, on the thread that dispatches Tauri commands.
    // Waiting on try_wait alone would not help: the direct child exits immediately in exactly
    // that case and the read is what blocks. So read on a worker and bound the wait.
    let mut command = Command::new(path);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // Never read, so never wait on it; piping without draining risks the child blocking.
        .stderr(Stdio::null())
        .env_remove("RUST_LOG");
    hide_console_window(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot run Aether core: {error}"))?;

    let stdout = child.stdout.take().expect("stdout is piped above");
    let (sender, receiver) = mpsc::channel();
    // ponytail: on timeout this thread stays blocked on a pipe nobody will close. Bounded by the
    // number of probes and it holds one buffer; revisit only if probing turns into a hot path.
    thread::spawn(move || {
        let mut buffer = Vec::new();
        // Cap the read so a chatty or hostile binary cannot balloon memory.
        let _ = stdout.take(64 * 1024).read_to_end(&mut buffer);
        let _ = sender.send(buffer);
    });

    let Ok(buffer) = receiver.recv_timeout(VERSION_PROBE_TIMEOUT) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Aether version check timed out".into());
    };
    let status = child
        .wait()
        .map_err(|error| format!("cannot run Aether core: {error}"))?;
    if !status.success() {
        return Err(format!("Aether version check failed with {status}"));
    }

    let version = String::from_utf8_lossy(&buffer).trim().to_string();
    if !version.to_ascii_lowercase().starts_with("aether ") {
        return Err("the selected executable is not an Aether core".into());
    }
    Ok(version)
}

fn profile_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|path| path.join("profiles").join("default.json"))
        .map_err(|error| format!("cannot resolve app config directory: {error}"))
}

fn transport_label(profile: &CoreProfile) -> &'static str {
    match (profile.protocol.as_str(), profile.masque_transport.as_str()) {
        ("masque", "h2") => "masque-h2",
        ("masque", _) => "masque-h3",
        ("wg", _) => "wireguard",
        _ => "warp-in-warp",
    }
}

/// What this attempt is actually configured with.
///
/// Zero Trust credentials are deliberately reduced to whether one is set. The
/// line ends up in diagnostics reports that leave the machine, and a team name
/// identifies the user even though it is not itself a secret.
fn session_summary(profile: &CoreProfile, attempt: u32) -> String {
    format!(
        "session transport={} scan={} ip={} noize={} fragment={} dataCheck={} quickReconnect={} \
         perf={} validate={}s startup={}s endpoint={} peerPinned={} zeroTrust={} gateway={} \
         attempt={attempt}",
        transport_label(profile),
        profile.scan_mode,
        profile.ip_family,
        profile.noize,
        profile.fragment_client_hello,
        profile.data_check,
        profile.quick_reconnect,
        profile.performance_profile,
        profile.validate_secs,
        profile.startup_secs,
        profile.endpoint_mode,
        non_empty(profile.peer.as_deref()).is_some(),
        non_empty(profile.team.as_deref()).is_some(),
        profile.gateway,
    )
}

/// The same transport, for a line the user reads.
fn transport_name(profile: &CoreProfile) -> &'static str {
    match transport_label(profile) {
        "masque-h2" => "MASQUE H2",
        "masque-h3" => "MASQUE H3",
        "wireguard" => "WireGuard",
        _ => "WARP in WARP",
    }
}

fn validate_peer(label: &str, value: Option<&str>) -> Result<(), String> {
    if let Some(value) = non_empty(value) {
        value
            .parse::<SocketAddr>()
            .map_err(|_| format!("{label} must be a valid IP:port"))?;
    }
    Ok(())
}

fn validate_range(label: &str, value: &str, minimum: u64, maximum: u64) -> Result<(), String> {
    let values: Vec<&str> = value.split('-').collect();
    if values.is_empty() || values.len() > 2 {
        return Err(format!("{label} must be a number or range"));
    }
    let mut parsed = Vec::new();
    for item in values {
        let number = item
            .parse::<u64>()
            .map_err(|_| format!("{label} must contain only positive numbers"))?;
        if number < minimum {
            return Err(format!("{label} must be at least {minimum}"));
        }
        if number > maximum {
            return Err(format!("{label} must not exceed {maximum}"));
        }
        parsed.push(number);
    }
    if parsed.len() == 2 && parsed[0] > parsed[1] {
        return Err(format!("{label} range must be ascending"));
    }
    Ok(())
}

fn validate_optional_text(label: &str, value: Option<&str>, maximum: usize) -> Result<(), String> {
    if let Some(value) = non_empty(value) {
        validate_text(label, value, maximum)?;
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, maximum: usize) -> Result<(), String> {
    if value.len() > maximum {
        return Err(format!("{label} is too long"));
    }
    if value.contains('\0') {
        return Err(format!("{label} contains an invalid character"));
    }
    Ok(())
}

fn set_optional_env(command: &mut Command, key: &str, value: Option<&str>) {
    if let Some(value) = non_empty(value) {
        command.env(key, value);
    }
}

fn require_one_of(label: &str, value: &str, options: &[&str]) -> Result<(), String> {
    if options.contains(&value) {
        Ok(())
    } else {
        Err(format!("unsupported {label}: {value}"))
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn core_filename() -> &'static str {
    if cfg!(windows) {
        "aether.exe"
    } else {
        "aether"
    }
}

fn log_level(message: &str) -> &'static str {
    if message.contains(" ERROR ") || message.starts_with("ERROR") {
        "error"
    } else if message.contains(" WARN ") || message.starts_with("WARN") {
        "warn"
    } else if message.contains(" DEBUG ") || message.starts_with("DEBUG") {
        "debug"
    } else if message.contains(" TRACE ") || message.starts_with("TRACE") {
        "trace"
    } else {
        "info"
    }
}

fn strip_logger_prefix(message: &str) -> String {
    // splitn, not split().last(): the intent is to drop the "timestamp LEVEL target - " prefix,
    // but " - " also occurs inside prose, and taking the last segment threw away everything
    // before the final separator ("gateway rejected - retrying without encryption" -> "done").
    message
        .splitn(2, " - ")
        .nth(1)
        .unwrap_or(message)
        .trim()
        .to_string()
}

/// Marks the snapshot as changed. The pump sends the latest one.
///
/// Coalescing matters as much as batching: a scan can change state several
/// times a second, and the window only ever needs the newest.
fn mark_snapshot_dirty(inner: &SupervisorInner) {
    inner.snapshot_dirty.store(true, Ordering::SeqCst);
}

/// Delivers buffered logs and snapshot changes to the window on a timer.
///
/// One thread for the life of the app. Emitting from the reader thread is what
/// let a slow window throttle the core -- this keeps the two apart, so the core
/// runs at full speed whether or not anything is listening.
pub fn start_pump(app: AppHandle, supervisor: &CoreSupervisor) {
    let inner = supervisor.inner.clone();
    let log_path = session_log_path(&app);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(120));

        let batch: Vec<CoreLogEvent> = {
            let mut pending = lock(&inner.pending);
            if pending.is_empty() {
                Vec::new()
            } else {
                std::mem::take(&mut *pending)
            }
        };
        if !batch.is_empty() {
            if let Some(path) = log_path.as_deref() {
                append_session_log(path, &batch);
            }
            let _ = app.emit("core-logs", &batch);
        }
        if inner.snapshot_dirty.swap(false, Ordering::SeqCst) {
            let snapshot = lock(&inner.snapshot).clone();
            let _ = app.emit("core-status", &snapshot);
        }
    });
}

/// Where this run's log is kept on disk.
///
/// The in-memory buffer holds the last {MAX_LOGS} lines and dies with the
/// process, which is exactly the wrong shape for the failures worth reporting:
/// a crash, a freeze, or a scan that took ten minutes and scrolled the evidence
/// away. Written from the pump, so the thread reading the core still never
/// waits on anything.
fn session_log_path(app: &AppHandle) -> Option<PathBuf> {
    let dir = app.path().app_log_dir().ok()?;
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join("core.log");
    // One rotation, so the file that survives a crash is still there after the
    // restart that follows it -- and the pair stays bounded.
    if std::fs::metadata(&path).is_ok_and(|meta| meta.len() > MAX_LOG_BYTES) {
        let _ = std::fs::rename(&path, dir.join("core.previous.log"));
    }
    Some(path)
}

/// Two megabytes: a few thousand lines, which covers a long scan and several
/// retries without letting an app left running for weeks fill a disk.
const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

fn append_session_log(path: &Path, batch: &[CoreLogEvent]) {
    let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let mut text = String::new();
    for event in batch {
        text.push_str(&format!(
            "{} [{}/{}] {}
",
            event.timestamp, event.stream, event.level, event.message
        ));
    }
    let _ = file.write_all(text.as_bytes());
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(windows)]
fn hide_console_window(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x08000000);
}

#[cfg(not(windows))]
fn hide_console_window(_command: &mut Command) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_is_valid_and_non_interactive() {
        let profile = CoreProfile::default();
        profile.validate().unwrap();
        let args = profile.args(Path::new("identity.toml"));
        assert!(args.windows(2).any(|pair| pair == ["--masque", "--scan"]));
        assert!(args.contains(&"--h2".to_string()));
        assert!(args.contains(&"--dual".to_string()) == false);
        assert!(args.windows(2).any(|pair| pair == ["--ip", "both"]));
        assert!(args.contains(&"--quick-reconnect".to_string()));
    }

    #[test]
    fn log_parser_only_connects_after_socks_listener() {
        let mut snapshot = CoreSnapshot::default();
        apply_log_to_snapshot(
            "[+] selected MASQUE gateway 162.159.192.18:443 (rtt 84.5ms)",
            &mut snapshot,
        );
        assert_eq!(snapshot.endpoint.as_deref(), Some("162.159.192.18:443"));
        assert_eq!(snapshot.latency_ms, Some(84.5));
        assert_ne!(snapshot.state, "connected");
        apply_log_to_snapshot(
            "[+] socks5 server listening on 127.0.0.1:1819",
            &mut snapshot,
        );
        assert_eq!(snapshot.state, "connected");
    }

    #[test]
    fn invalid_values_are_rejected() {
        let mut profile = CoreProfile::default();
        profile.socks_address = "localhost".into();
        assert!(profile.validate().is_err());
        profile = CoreProfile::default();
        profile.fragment_size = "32-16".into();
        assert!(profile.validate().is_err());
    }

    #[test]
    fn state_detection_survives_a_quiet_log_level() {
        // Below info the core stops printing the lines the snapshot is derived
        // from, so the process floor is info however quiet the profile asks for.
        for level in ["error", "warn", "info"] {
            let mut profile = CoreProfile::default();
            profile.log_level = level.into();
            profile.validate().unwrap();
            assert_eq!(profile.process_log_level(), "info");
        }
        let mut profile = CoreProfile::default();
        profile.log_level = "trace".into();
        assert_eq!(profile.process_log_level(), "trace");
        let args = profile.args(Path::new("identity.toml"));
        assert!(args.windows(2).any(|pair| pair == ["--log-level", "trace"]));
    }

    #[test]
    fn retries_alternate_masque_transports() {
        let profile = CoreProfile::default();
        assert_eq!(profile.masque_transport, "h2");
        // The first retry switches, because it follows two minutes of evidence
        // that the configured transport is not getting out. Then it alternates,
        // so a network that blocks UDP is not retried eight times over QUIC.
        for (attempt, expected) in [(0, "h2"), (1, "h3"), (2, "h2"), (3, "h3"), (4, "h2")] {
            assert_eq!(
                profile_for_attempt(&profile, attempt).masque_transport,
                expected,
                "attempt {attempt}",
            );
        }
    }

    #[test]
    fn retries_leave_single_transport_protocols_alone() {
        let mut profile = CoreProfile::default();
        profile.protocol = "wg".into();
        for attempt in 0..=MAX_ATTEMPTS {
            let attempted = profile_for_attempt(&profile, attempt);
            assert_eq!(attempted.protocol, "wg");
            assert_eq!(attempted.masque_transport, profile.masque_transport);
        }
    }

    #[test]
    fn alternating_transport_rebuilds_the_arguments_for_it() {
        let profile = CoreProfile::default();
        let h2 = profile_for_attempt(&profile, 2).args(Path::new("identity.toml"));
        let h3 = profile_for_attempt(&profile, 1).args(Path::new("identity.toml"));
        assert!(h2.contains(&"--h2".to_string()));
        assert!(h2.contains(&"--fragment".to_string()));
        // Fragmentation is an HTTP/2 measure; carrying it onto QUIC would pass
        // the core an argument that does not apply to the transport it is using.
        assert!(!h3.contains(&"--h2".to_string()));
        assert!(!h3.contains(&"--fragment".to_string()));
    }

    fn session(generation: u64, attempt: u32) -> Option<Session> {
        Some(Session {
            generation,
            profile: CoreProfile::default(),
            attempt,
        })
    }

    #[test]
    fn exits_count_up_to_the_limit_then_give_up() {
        let mut current = session(1, 0);
        for expected in 1..=MAX_ATTEMPTS {
            match decide_exit(&mut current, 1, false) {
                ExitDecision::Retry { attempt, .. } => assert_eq!(attempt, expected),
                other => panic!("attempt {expected} decided {other:?}"),
            }
        }
        assert!(matches!(
            decide_exit(&mut current, 1, false),
            ExitDecision::GiveUp { .. }
        ));
        // Giving up ends the session, so a later stray exit changes nothing.
        assert!(current.is_none());
        assert!(matches!(decide_exit(&mut current, 1, false), ExitDecision::Ignore));
    }

    #[test]
    fn a_late_exit_never_disturbs_a_newer_session() {
        // A stop and a fresh start can both land between a core exiting and the
        // supervisor noticing. The old generation must not touch the new
        // session -- clearing it would silently cost the new connection every
        // retry it is entitled to.
        let mut current = session(2, MAX_ATTEMPTS);
        assert!(matches!(decide_exit(&mut current, 1, false), ExitDecision::Ignore));
        assert_eq!(current.as_ref().unwrap().generation, 2);
        assert_eq!(current.as_ref().unwrap().attempt, MAX_ATTEMPTS);

        let mut stopped = None;
        assert!(matches!(decide_exit(&mut stopped, 1, false), ExitDecision::Ignore));
    }

    #[test]
    fn a_held_block_never_ends_the_session() {
        // The whole point of the hold: a kill switch that stops trying leaves
        // the machine behind a proxy with nothing behind it, waiting to be
        // noticed. Running out of attempts must reset the budget, not give up.
        let mut current = session(1, MAX_ATTEMPTS);
        assert!(matches!(
            decide_exit(&mut current, 1, true),
            ExitDecision::Hold { .. }
        ));
        assert!(current.is_some(), "holding must keep the session alive");
        assert_eq!(
            current.as_ref().unwrap().attempt,
            0,
            "the retry budget has to reset, or the next exit gives up anyway"
        );

        // And it keeps holding, rather than holding once and then stranding.
        for _ in 0..(MAX_ATTEMPTS + 2) {
            let decision = decide_exit(&mut current, 1, true);
            assert!(
                matches!(decision, ExitDecision::Retry { .. } | ExitDecision::Hold { .. }),
                "a held session decided {decision:?}",
            );
            assert!(current.is_some());
        }
    }

    #[test]
    fn a_hold_stops_the_moment_traffic_is_no_longer_held() {
        // Turning the kill switch off, or the proxy coming back, has to let the
        // session end normally -- otherwise it retries forever in the background.
        let mut current = session(1, MAX_ATTEMPTS);
        assert!(matches!(
            decide_exit(&mut current, 1, false),
            ExitDecision::GiveUp { .. }
        ));
        assert!(current.is_none());
    }

    #[test]
    fn declining_to_reconnect_still_holds_when_traffic_is_blocked() {
        // "Keep me connected" off means do not chase a dead route. It cannot
        // mean leave the machine blocked with nothing trying to unblock it.
        let mut profile = CoreProfile::default();
        profile.auto_reconnect = false;
        profile.kill_switch = true;
        let mut current = Some(Session { generation: 1, profile, attempt: 0 });
        assert!(matches!(
            decide_exit(&mut current, 1, true),
            ExitDecision::Hold { .. }
        ));
        assert!(current.is_some());
    }

    #[test]
    fn a_sweep_that_found_nothing_is_recognised() {
        // Verbatim from a Windows 1.2.0 session that sat on "Searching" for
        // twenty-six minutes: the core repeated the same H2 sweep because it
        // never exited, so no retry of ours ever ran.
        for line in [
            "[2026-08-14T06:25:02.686Z WARN  aether] [-] no usable MASQUE gateway found: prober: \
             no clean endpoint found; rescanning shortly",
            "[2026-08-14T06:25:02.685Z WARN  aether::prober] [-] scan deadline reached with no gateway",
        ] {
            assert!(sweep_exhausted(line), "not recognised: {line}");
        }
    }

    #[test]
    fn ordinary_scanning_lines_do_not_end_a_sweep() {
        // Killing the core mid-search would be far worse than the stall: these
        // are what a healthy sweep looks like on its way to succeeding.
        for line in [
            "[*] hunting for a working MASQUE gateway (deep connect-ip + data-plane verification)",
            "[*] scan mode=balanced ip=dual-stack candidates=3012 ports=[443] concurrency=16 \
             per_probe=6s budget=120s",
            "[+] obfuscation profile: balanced",
            "tls verification: pin-based (2 pins loaded)",
            "[+] selected MASQUE gateway 162.159.198.7:443 (rtt 71.4ms)",
            "[+] identity ready: device=5571c9de ipv4=0.0.0.0:0",
        ] {
            assert!(!sweep_exhausted(line), "would have killed a live scan: {line}");
        }
    }

    fn pinned(mode: &str) -> CoreProfile {
        let mut profile = CoreProfile::default();
        profile.endpoint_mode = mode.into();
        profile.peer = Some("162.159.192.18:443".into());
        profile
    }

    #[test]
    fn an_address_is_only_forced_when_the_mode_asks_for_it() {
        let mut automatic = CoreProfile::default();
        automatic.peer = Some("162.159.192.18:443".into());
        automatic.validate().unwrap();
        let args = automatic.args(Path::new("identity.toml"));
        assert!(!args.contains(&"--peer".to_string()), "{args:?}");

        for mode in ["custom-first", "custom-only"] {
            let profile = pinned(mode);
            profile.validate().unwrap();
            let args = profile.args(Path::new("identity.toml"));
            assert!(args.windows(2).any(|pair| pair == ["--peer", "162.159.192.18:443"]));
        }
    }

    #[test]
    fn pinning_an_endpoint_requires_an_address() {
        for mode in ["custom-first", "custom-only"] {
            let mut profile = CoreProfile::default();
            profile.endpoint_mode = mode.into();
            assert!(profile.validate().is_err(), "{mode} accepted an empty peer");
            profile.peer = Some("   ".into());
            assert!(profile.validate().is_err(), "{mode} accepted a blank peer");
        }
        let mut unknown = CoreProfile::default();
        unknown.endpoint_mode = "custom".into();
        assert!(unknown.validate().is_err());
    }

    #[test]
    fn custom_first_stops_pinning_after_one_failure() {
        let base = pinned("custom-first");
        let first = profile_for_attempt(&base, 0);
        assert_eq!(first.endpoint_mode, "custom-first");
        assert!(first.args(Path::new("i.toml")).contains(&"--peer".to_string()));
        assert!(!fell_back_to_discovery(&base, &first));

        for attempt in 1..=MAX_ATTEMPTS {
            let retry = profile_for_attempt(&base, attempt);
            assert_eq!(retry.endpoint_mode, "automatic", "attempt {attempt}");
            assert!(!retry.args(Path::new("i.toml")).contains(&"--peer".to_string()));
            assert!(fell_back_to_discovery(&base, &retry));
            // The address stays in the profile so it is still in the field the
            // user typed it into.
            assert_eq!(retry.peer.as_deref(), Some("162.159.192.18:443"));
        }
    }

    #[test]
    fn custom_only_keeps_pinning_for_every_attempt() {
        let base = pinned("custom-only");
        for attempt in 0..=MAX_ATTEMPTS {
            let retry = profile_for_attempt(&base, attempt);
            assert_eq!(retry.endpoint_mode, "custom-only", "attempt {attempt}");
            assert!(retry.args(Path::new("i.toml")).contains(&"--peer".to_string()));
            assert!(!fell_back_to_discovery(&base, &retry));
        }
    }

    #[test]
    fn fallback_and_transport_alternation_apply_together() {
        // Independent axes: a pinned H2 endpoint that fails should be retried
        // over H3 discovery, not just one or the other. Both land on the first
        // retry, which is the one that follows a sweep proving H2 got nowhere.
        let base = pinned("custom-first");
        let first = profile_for_attempt(&base, 1);
        assert_eq!(first.endpoint_mode, "automatic");
        assert_eq!(first.masque_transport, "h3");
    }

    #[test]
    fn a_profile_saved_before_endpoint_modes_keeps_forcing_its_address() {
        let mut stored = serde_json::json!({"peer": "162.159.192.18:443"});
        migrate_endpoint_mode(&mut stored);
        assert_eq!(stored["endpointMode"], "custom-only");

        // Nothing pinned, nothing to preserve.
        let mut empty = serde_json::json!({"peer": ""});
        migrate_endpoint_mode(&mut empty);
        assert!(empty.get("endpointMode").is_none());
        let mut none = serde_json::json!({"name": "Adaptive"});
        migrate_endpoint_mode(&mut none);
        assert!(none.get("endpointMode").is_none());

        // An explicit choice is never overwritten.
        let mut explicit =
            serde_json::json!({"peer": "162.159.192.18:443", "endpointMode": "custom-first"});
        migrate_endpoint_mode(&mut explicit);
        assert_eq!(explicit["endpointMode"], "custom-first");
    }

    #[test]
    fn report_names_cannot_climb_out_of_the_reports_directory() {
        assert_eq!(
            sanitize_report_name("whiteaesther-20260812-140301.txt").unwrap(),
            "whiteaesther-20260812-140301.txt"
        );
        for rejected in [
            "../escape.txt",
            "..\\escape.txt",
            "sub/dir.txt",
            "report.exe",
            ".hidden.txt",
            "report.txt\0",
            "",
        ] {
            assert!(
                sanitize_report_name(rejected).is_err(),
                "accepted {rejected:?}"
            );
        }
    }

    #[test]
    fn a_failed_listener_is_never_reported_as_connected() {
        for line in [
            "failed to bind: socks5 server listening on 127.0.0.1:1819 already in use",
            "2026-01-01 ERROR core - could not start socks5 server listening on 127.0.0.1:1819",
            "WARN peer sent banner: \"socks5 server listening on 0.0.0.0:9\"",
        ] {
            let mut snapshot = CoreSnapshot::default();
            apply_log_to_snapshot(line, &mut snapshot);
            assert_ne!(snapshot.state, "connected", "line must not connect: {line}");
        }
    }

    #[test]
    fn session_summary_never_carries_zero_trust_values() {
        let mut profile = CoreProfile::default();
        profile.team = Some("acme".into());
        profile.access_client_secret = Some("super-secret".into());
        profile.access_token = Some("token-value".into());
        profile.access_email = Some("someone@example.com".into());
        let summary = session_summary(&profile, 0);
        assert!(summary.contains("zeroTrust=true"));
        for secret in ["acme", "super-secret", "token-value", "someone@example.com"] {
            assert!(!summary.contains(secret), "{secret} leaked into {summary}");
        }
    }

    #[test]
    fn retry_delay_widens_then_settles() {
        let delays: Vec<u64> = (1..=MAX_ATTEMPTS)
            .map(|attempt| retry_delay(attempt).as_secs())
            .collect();
        assert_eq!(delays, vec![3, 6, 12, 24, 48, 60, 60, 60]);
    }

    #[test]
    fn socks_address_is_only_taken_from_a_valid_gated_address() {
        // Garbage after the gate leaves the configured value untouched.
        let mut snapshot = CoreSnapshot::default();
        let configured = snapshot.socks_address.clone();
        apply_log_to_snapshot("socks5 server listening on not-an-address", &mut snapshot);
        assert_eq!(snapshot.socks_address, configured);

        // A different listener earlier in the line must not be mistaken for the SOCKS one.
        let mut snapshot = CoreSnapshot::default();
        apply_log_to_snapshot(
            "http proxy listening on 198.51.100.9:8080; socks5 server listening on 127.0.0.1:1819",
            &mut snapshot,
        );
        assert_eq!(snapshot.socks_address, "127.0.0.1:1819");
        assert_eq!(snapshot.state, "connected");
    }

    #[test]
    fn an_error_is_recorded_even_when_the_line_mentions_reconnecting() {
        let mut snapshot = CoreSnapshot::default();
        apply_log_to_snapshot(
            "2026-01-01 ERROR aether - TLS certificate verification FAILED, reconnecting",
            &mut snapshot,
        );
        assert_eq!(snapshot.state, "reconnecting");
        assert_eq!(
            snapshot.last_error.as_deref(),
            Some("TLS certificate verification FAILED, reconnecting")
        );
    }

    #[test]
    fn logger_prefix_strip_keeps_everything_after_the_first_separator() {
        assert_eq!(
            strip_logger_prefix("ERROR gateway rejected - retrying without encryption - done"),
            "retrying without encryption - done"
        );
    }

    #[test]
    fn whole_machine_follows_a_ready_chain_instead_of_warp() {
        let tunnel = "127.0.0.1:1819".parse().unwrap();
        let chain = "127.0.0.1:1820".parse().unwrap();
        assert_eq!(
            desired_proxy_route(true, Some(chain), Some(tunnel)),
            Some(ProxyRoute::Chain(chain))
        );
    }

    #[test]
    fn a_listening_chain_counts_as_requested_whatever_the_profile_says() {
        // The two can disagree: the chain is started from its own screen and
        // the carry mode is read from the session profile. When they did, Whole
        // machine sent the OS to WARP while the very same connection was being
        // advertised to applications as the chain's port.
        assert!(chain_is_in_play(true, false));
        assert!(chain_is_in_play(false, true));
        assert!(!chain_is_in_play(false, false));
    }

    #[test]
    fn whole_machine_waits_for_a_requested_chain_instead_of_leaking_to_warp() {
        let tunnel = "127.0.0.1:1819".parse().unwrap();
        assert_eq!(desired_proxy_route(true, None, Some(tunnel)), None);
    }

    #[test]
    fn whole_machine_uses_warp_when_no_chain_was_requested() {
        let tunnel = "127.0.0.1:1819".parse().unwrap();
        assert_eq!(
            desired_proxy_route(false, None, Some(tunnel)),
            Some(ProxyRoute::Tunnel(tunnel))
        );
    }

    #[test]
    fn an_applied_warp_route_is_not_mistaken_for_the_chain() {
        let tunnel = ProxyRoute::Tunnel("127.0.0.1:1819".parse().unwrap());
        let chain = ProxyRoute::Chain("127.0.0.1:1820".parse().unwrap());
        assert!(proxy_route_needs_update(Some(tunnel), chain));
        assert!(!proxy_route_needs_update(Some(chain), chain));
    }

    #[test]
    fn keepalive_matches_the_other_client_rather_than_the_engine_floor() {
        // The engine falls back to 5, which is five times noisier on the wire
        // than it needs to be, and the Android client settled on 25. Two
        // clients of the same engine holding the same mapping open at
        // different rates is a difference nobody chose.
        assert_eq!(CoreProfile::default().keepalive_secs, 25);
    }

    #[test]
    fn a_profile_still_on_the_old_keepalive_default_is_moved_up() {
        // Every profile written by an older build carries 5 whether or not
        // anyone chose it, so without this only fresh installs would ever see
        // the new interval.
        let mut stored = serde_json::json!({"keepaliveSecs": 5});
        migrate_keepalive(&mut stored);
        assert_eq!(stored["keepaliveSecs"], 25);
    }

    #[test]
    fn a_keepalive_someone_actually_typed_is_left_alone() {
        // Only the exact old default moves. Any other number was a decision,
        // and overriding a decision is worse than the drift this fixes.
        for chosen in [1, 4, 6, 25, 60, 300] {
            let mut stored = serde_json::json!({"keepaliveSecs": chosen});
            migrate_keepalive(&mut stored);
            assert_eq!(stored["keepaliveSecs"], chosen, "{chosen} was chosen and must stand");
        }
        // And a profile that never had the key keeps not having it, so the
        // struct default applies rather than a number invented here.
        let mut absent = serde_json::json!({"protocol": "masque"});
        migrate_keepalive(&mut absent);
        assert!(absent.get("keepaliveSecs").is_none());
    }

    #[test]
    fn zero_keepalive_leaves_the_engine_to_choose() {
        // Same contract as the Android client: saying nothing is how the one
        // default is kept in the engine instead of copied out here.
        let mut profile = CoreProfile { keepalive_secs: 0, ..CoreProfile::default() };
        assert!(profile.validate().is_ok(), "zero is a valid choice, not a typo");
        let args = profile.args(Path::new("identity.toml"));
        assert!(!args.contains(&"--keepalive".to_string()), "{args:?}");

        profile.keepalive_secs = 25;
        let args = profile.args(Path::new("identity.toml"));
        assert!(args.windows(2).any(|pair| pair == ["--keepalive", "25"]), "{args:?}");
    }

    #[test]
    fn the_two_engine_defaults_are_only_written_to_turn_them_off() {
        // Both are on in the engine and switched off by the literal "0". A
        // profile written before they existed has to read as on, or upgrading
        // would quietly change how traffic is routed.
        let fresh = CoreProfile::default();
        assert!(fresh.route_sniff);
        assert!(fresh.auto_reprovision);

        let older: CoreProfile = serde_json::from_str(r#"{"protocol":"masque"}"#)
            .expect("a profile from before these existed must load");
        assert!(older.route_sniff, "sniffing is on unless someone turned it off");
        assert!(older.auto_reprovision, "reprovisioning is on unless someone turned it off");
    }

    #[test]
    fn an_upstream_proxy_never_reaches_the_command_line() {
        // The URL can carry a password, and a command line is readable by
        // anything that can list processes. It goes in the environment for the
        // same reason the Zero Trust secret does.
        let profile = CoreProfile {
            upstream_proxy: "socks5://someone:hunter2@127.0.0.1:1080".into(),
            ..CoreProfile::default()
        };
        let args = profile.args(Path::new("identity.toml"));
        let rendered = args.join(" ");
        assert!(!rendered.contains("hunter2"), "a password must not be an argument: {rendered}");
        assert!(!rendered.contains("--upstream"), "{rendered}");
        assert!(!rendered.contains("127.0.0.1:1080"), "{rendered}");
    }

    #[test]
    fn a_full_tunnel_wish_that_cannot_be_honoured_is_not_a_failure() {
        // The wish outlives any one launch, so it is routinely on in a copy
        // with no permission to honour it. That must cost nothing: the engine
        // still starts and the exit chain still runs. Treating it as a failure
        // is what turned a missing permission into a connection that would not
        // come up at all.
        let inner = CoreSupervisor::new().inner;
        assert!(!tun_is_possible(&inner, false), "not wanted is not possible");
        // Wanted and permitted is the only true case, and whether this test
        // process is elevated is not something it may assume either way -- so
        // assert the part that holds regardless: it answers rather than panics,
        // and it never says yes when the wish was never made.
        let _ = tun_is_possible(&inner, true);
    }

    #[test]
    fn a_profile_saved_before_the_iran_bypass_existed_still_loads_with_it_off() {
        // Upgrading must not change how anyone's traffic is routed. A profile
        // written by an older build has no such key, and the absence has to
        // read as "off" rather than as a parse failure that resets everything
        // else the user had configured.
        let saved = serde_json::json!({
            "name": "Adaptive",
            "protocol": "masque",
            "socksAddress": "127.0.0.1:1819",
            "routeDirect": "example.com"
        })
        .to_string();
        let profile: CoreProfile = serde_json::from_str(&saved).expect("an older profile must load");
        assert!(!profile.bypass_iran_sites, "the new setting must default to off");
        assert_eq!(profile.route_direct, "example.com", "existing rules must survive");
        assert_eq!(profile.socks_address, "127.0.0.1:1819");
    }

    #[test]
    fn a_zero_fragment_size_is_rejected_but_a_zero_delay_is_allowed() {
        let mut profile = CoreProfile::default();
        profile.fragment_size = "0".into();
        assert!(profile.validate().is_err());

        profile = CoreProfile::default();
        profile.fragment_size = "0-0".into();
        assert!(profile.validate().is_err());

        profile = CoreProfile::default();
        profile.fragment_delay = "0".into();
        profile.validate().unwrap();
    }
}

/// A headless stand-in for [`launch`], for pinning down "works in a terminal,
/// not in the app". Run it with the app closed:
///
///     cargo test spawn_like_the_app -- --ignored --nocapture
///
/// It builds the child exactly as `launch` does -- same arguments, working
/// directory, environment, piped stdio and creation flags -- and prints each
/// line with the milliseconds since spawn, so the point where the two diverge
/// is visible rather than inferred.
#[cfg(test)]
mod spawn_repro {
    use super::*;

    #[test]
    #[ignore = "spawns the real core and talks to the network"]
    fn spawn_like_the_app() {
        let config_dir = PathBuf::from(std::env::var("WHITEAESTHER_CONFIG_DIR").expect(
            "set WHITEAESTHER_CONFIG_DIR to the app config directory",
        ));
        let core_path = PathBuf::from(
            std::env::var("WHITEAESTHER_CORE_PATH").expect("set WHITEAESTHER_CORE_PATH"),
        );
        let identity_path = config_dir.join("identity").join("aether.toml");
        let profile = CoreProfile::default();

        let mut command = Command::new(&core_path);
        command
            .args(profile.args(&identity_path))
            .current_dir(&config_dir)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        hide_console_window(&mut command);

        let started = Instant::now();
        let mut child = command.spawn().expect("spawn");
        let stdout = child.stdout.take().expect("stdout");
        let stderr = child.stderr.take().expect("stderr");
        for (reader, name) in [
            (Box::new(stdout) as Box<dyn Read + Send>, "out"),
            (Box::new(stderr) as Box<dyn Read + Send>, "err"),
        ] {
            thread::spawn(move || {
                for line in BufReader::new(reader).lines().map_while(Result::ok) {
                    println!("[{:>6}ms {name}] {line}", started.elapsed().as_millis());
                }
            });
        }
        thread::sleep(Duration::from_secs(45));
        let _ = child.kill();
        let _ = child.wait();
    }
}
