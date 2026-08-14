use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    io::{BufRead, BufReader, Read},
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
use crate::http_bridge::{self, HttpBridge};
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
    /// Leave the system proxy pointed at the dead listener when the tunnel
    /// fails, so applications that follow it fail rather than send the traffic
    /// in the clear.
    ///
    /// The cost is real: until the tunnel comes back or the app is closed, the
    /// machine has no working proxy. Off by default for that reason.
    pub kill_switch: bool,
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
            keepalive_secs: 5,
            auto_reconnect: true,
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
        if !(1..=300).contains(&self.keepalive_secs) {
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
            "--keepalive".into(),
            self.keepalive_secs.to_string(),
            "--log-level".into(),
            self.process_log_level().into(),
            "--config".into(),
            identity_path.to_string_lossy().into_owned(),
        ];

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

struct SupervisorInner {
    child: Mutex<Option<Child>>,
    snapshot: Mutex<CoreSnapshot>,
    logs: Mutex<VecDeque<CoreLogEvent>>,
    session: Mutex<Option<Session>>,
    /// Bumped by every start and every stop. A retry thread that wakes up on a
    /// stale generation has been superseded and does nothing.
    generation: AtomicU64,
    /// Whether this process has the system proxy pointed at its listener.
    proxy_applied: AtomicBool,
    /// A reporting run of the core -- a scan or an endpoint test. Separate from
    /// `child` because it is short-lived and independently cancellable.
    scan_child: Mutex<Option<Child>>,
    /// The local HTTP proxy the system proxy points at. Only alive while the
    /// system proxy is applied, and dropped with it.
    bridge: Mutex<Option<HttpBridge>>,
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
                proxy_applied: AtomicBool::new(false),
                scan_child: Mutex::new(None),
                bridge: Mutex::new(None),
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

    let mut command = Command::new(&core_path);
    command
        .args(profile.args(&identity_path))
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
        emit_snapshot(app, &snapshot);
    }
    supervisor_log(app, inner, "info", session_summary(profile, attempt));

    if let Some(stdout) = stdout {
        spawn_log_reader(app.clone(), inner.clone(), stdout, "stdout");
    }
    if let Some(stderr) = stderr {
        spawn_log_reader(app.clone(), inner.clone(), stderr, "stderr");
    }
    spawn_exit_monitor(app.clone(), inner.clone(), generation);

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
    // Before the listener exists there is nothing to point at; the connect path
    // applies it when the core reports itself up.
    if state != "connected" {
        return Ok(false);
    }
    apply_system_proxy(&app, inner, &socks);
    Ok(inner.proxy_applied.load(Ordering::SeqCst))
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
    let profile: CoreProfile =
        serde_json::from_value(stored).map_err(|error| format!("profile is invalid: {error}"))?;
    profile.validate()?;
    Ok(profile)
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
        emit_snapshot(app, &snapshot);
    }
    supervisor_log(
        app,
        inner,
        "error",
        format!("gave up after {MAX_ATTEMPTS} attempts: {reason}"),
    );

    // The kill switch only bites here, on the failure path. An explicit stop and
    // a quit both restore unconditionally, so the machine can always be put back
    // by disconnecting or closing the app — and a kill rather than a close is
    // caught by the recovery pass at the next launch.
    if profile.kill_switch && inner.proxy_applied.load(Ordering::SeqCst) {
        supervisor_log(
            app,
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
            && inner.proxy_applied.load(Ordering::SeqCst)
    };
    let decision = decide_exit(&mut lock(&inner.session), generation, holding);
    let (attempt, base_profile) = match decision {
        ExitDecision::Ignore => return,
        ExitDecision::GiveUp { profile } => return give_up(app, inner, generation, &profile, reason),
        ExitDecision::Hold { profile } => return hold(app, inner, generation, profile, reason),
        ExitDecision::Retry { attempt, profile } => (attempt, profile),
    };

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
        emit_snapshot(app, &snapshot);
    }
    if fell_back {
        supervisor_log(
            app,
            inner,
            "warn",
            format!(
                "custom endpoint {} failed; falling back to automatic discovery",
                base_profile.peer.as_deref().unwrap_or("(unset)")
            ),
        );
    }
    supervisor_log(
        app,
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
        emit_snapshot(app, &snapshot);
    }
    supervisor_log(
        app,
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

fn push_log(app: &AppHandle, inner: &SupervisorInner, stream: &str, level: &str, message: String) {
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
    let _ = app.emit("core-log", &event);
}

/// What the supervisor itself did, as opposed to what the core printed.
///
/// Retries, give-ups and the configuration a session ran with leave no trace in
/// the core's own output, so without these a diagnostics report cannot answer
/// the question it was collected for.
fn supervisor_log(app: &AppHandle, inner: &SupervisorInner, level: &str, message: String) {
    push_log(app, inner, "supervisor", level, message);
}

fn record_log(app: &AppHandle, inner: &SupervisorInner, stream: &str, message: String) {
    let message = message.trim().to_string();
    push_log(app, inner, stream, log_level(&message), message.clone());

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
                emit_snapshot(app, &snapshot);
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
        end_fruitless_sweep(app, inner);
    }

    // A tunnel that came up has spent its failures. Anything after this is a
    // fresh problem and gets the full retry budget again. Kept out of the
    // snapshot lock above so the two are never held at once.
    if connected {
        let wanted = {
            let mut guard = lock(&inner.session);
            match guard.as_mut() {
                Some(session) => {
                    session.attempt = 0;
                    session.profile.system_proxy
                }
                None => false,
            }
        };
        if wanted {
            let socks = lock(&inner.snapshot).socks_address.clone();
            apply_system_proxy(app, inner, &socks);
        }
    }
}

/// Points the OS at the tunnel. Idempotent, so the log-line path and the
/// change-while-connected path can both call it.
fn apply_system_proxy(app: &AppHandle, inner: &SupervisorInner, socks: &str) {
    if inner.proxy_applied.load(Ordering::SeqCst) {
        return;
    }
    let Ok(address) = socks.parse::<SocketAddr>() else {
        supervisor_log(
            app,
            inner,
            "warn",
            format!("cannot use {socks} as a system proxy address"),
        );
        return;
    };

    // Windows follows an HTTP proxy and effectively ignores a SOCKS one, so the
    // bridge is what its settings are pointed at. It costs a listener on
    // loopback and is torn down with the proxy.
    let bridge = match http_bridge::start(address) {
        Ok(bridge) => bridge,
        Err(error) => {
            supervisor_log(
                app,
                inner,
                "warn",
                format!("could not start the local HTTP proxy: {error}"),
            );
            return;
        }
    };
    let targets = ProxyTargets { socks: address, http: bridge.address() };
    *lock(&inner.bridge) = Some(bridge);

    match system_proxy::apply(app, targets) {
        Ok(()) => {
            inner.proxy_applied.store(true, Ordering::SeqCst);
            supervisor_log(
                app,
                inner,
                "info",
                format!("system proxy set to {} via {}", targets.socks, targets.http),
            );
        }
        // Worth saying and worth continuing: the tunnel is up either way, and
        // the SOCKS listener can still be used directly.
        Err(error) => {
            // Nothing is pointed at the bridge, so it has no reason to stay up.
            lock(&inner.bridge).take();
            supervisor_log(
                app,
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
    // Whatever else happens, the proxy is going back, so nothing is held any
    // more. Cleared unconditionally: the flag must never outlive the block, or
    // the screen tells the user they are protected when they are not.
    {
        let mut snapshot = lock(&inner.snapshot);
        if snapshot.blocking {
            snapshot.blocking = false;
            emit_snapshot(app, &snapshot);
        }
    }
    if !inner.proxy_applied.swap(false, Ordering::SeqCst) {
        return;
    }
    // Dropped before the settings change, so nothing can be sent to a bridge
    // that is about to stop answering.
    lock(&inner.bridge).take();
    match system_proxy::revert(app) {
        Ok(()) => supervisor_log(app, inner, "info", "system proxy restored".into()),
        Err(error) => {
            // Leave the flag cleared but say so loudly: the backup file stays on
            // disk, so the next launch will try again.
            supervisor_log(
                app,
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
fn end_fruitless_sweep(app: &AppHandle, inner: &SupervisorInner) {
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
        app,
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
    emit_snapshot(app, &snapshot);
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

fn emit_snapshot(app: &AppHandle, snapshot: &CoreSnapshot) {
    let _ = app.emit("core-status", snapshot);
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
