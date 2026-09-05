//! Psiphon as a carrier: a supervised child ending in a SOCKS5 listener.
//!
//! Deliberately not built on [`crate::core_supervisor`]. That file is a
//! supervisor for the Aether engine specifically -- it reads connection state
//! out of log prose, alternates H2 and H3 when a transport is blocked, kills a
//! sweep that found nothing, and re-scans a gateway that went slow. None of it
//! applies here. `psiphon-tunnel-core` finds its own way out, retries on its
//! own, reconnects on its own, and says what it is doing in structured JSON.
//! Reusing that machinery would mean fighting a second retry loop layered on
//! one that is already better informed than we are.
//!
//! What is shared is the shape: spawn a child, drain both pipes so it cannot
//! block on its own logging, watch for it to exit, and end in an address
//! [`crate::chain`] can route into.
//!
//! ## The notices
//!
//! The console client writes one JSON object per line to **stderr**. Read from
//! tunnel-core's own source rather than inferred, because two of them are easy
//! to get subtly wrong:
//!
//! - `ListeningSocksProxyPort` is the listener, and it comes up *before* there
//!   is a tunnel behind it. Reporting connected here would hand the chain a
//!   proxy with nowhere to forward to, which swallows packets rather than
//!   refusing them -- the same fault as reporting tor connected before its
//!   circuit is built.
//! - `Tunnels` carries the count, and that is the connected signal. Upstream's
//!   own comment says "when count > 1, the core is connected"; that is an
//!   off-by-one in their documentation, since one tunnel plainly is connected.
//!   The code says `count > 0`, which is what the notice means.

use std::{
    collections::VecDeque,
    io::{BufRead, BufReader},
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::carrier::{Carrier, CarrierKind};
use crate::core_supervisor::CoreSupervisor;

/// How long to wait for a tunnel before calling it a failure.
///
/// Matches `EstablishTunnelTimeoutSeconds` in the config, plus a margin for the
/// process to start and for the notice to reach us. Bounded on purpose:
/// tunnel-core's own default is unlimited, and an unlimited establish is a
/// carrier that never reports failure -- the screen would say "connecting"
/// until the app was closed.
const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(135);

/// What the config asks tunnel-core for. Kept just under [`ESTABLISH_TIMEOUT`]
/// so the process gives up first and says why, rather than being killed by us
/// with nothing to report.
const ESTABLISH_TUNNEL_TIMEOUT_SECONDS: u64 = 120;

/// Psiphon's documented values for a client that has not been issued its own.
///
/// `PropagationChannelId` and `SponsorId` say who distributed a client so that
/// Psiphon can attribute usage and plan capacity. Real ones are issued by
/// Psiphon Inc. to partners; these are the all-Fs and all-1s placeholders that
/// appear throughout tunnel-core's own tests and in every open-source client
/// that has not asked for a channel of its own.
///
/// They are not credentials and nothing is authenticated by them. What they
/// cost is that our sessions are indistinguishable from every other
/// unattributed client, so Psiphon cannot tell our users apart from anyone
/// else's when planning capacity. If this carrier turns out to matter to the
/// people using it, asking Psiphon for a channel is a conversation rather than
/// a patch.
const PROPAGATION_CHANNEL_ID: &str = "FFFFFFFFFFFFFFFF";
const SPONSOR_ID: &str = "1111111111111111";

#[cfg(windows)]
const PSIPHON_FILENAME: &str = "psiphon-tunnel-core.exe";
#[cfg(not(windows))]
const PSIPHON_FILENAME: &str = "psiphon-tunnel-core";

/// The bootstrap list, staged beside the binary by `scripts/stage-psiphon.mjs`.
const SERVER_LIST_FILENAME: &str = "psiphon_server_entries.txt";

/// How much of the notice stream to keep for diagnostics.
///
/// tunnel-core emits hundreds of notices while establishing -- 499 in one
/// measured connect. Forwarding all of them to the shared log would evict the
/// engine's own entries from its buffer, so the state changes and the failures
/// go there and the rest is kept here, where a report can still reach it.
const MAX_NOTICES: usize = 400;

/// What the user chose about how Psiphon should run.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct PsiphonSettings {
    /// A two-letter country to exit from, or empty for whichever Psiphon
    /// considers best.
    ///
    /// A preference and not a guarantee: tunnel-core treats an unreachable
    /// region as a reason to keep trying rather than to substitute, so naming a
    /// country with no capacity is a slow connect rather than a different exit
    /// than the one asked for. Empty is the default for that reason.
    pub egress_region: String,
}

impl PsiphonSettings {
    pub(crate) fn validate(&self) -> Result<(), String> {
        let region = self.egress_region.trim();
        if region.is_empty() {
            return Ok(());
        }
        if region.len() == 2 && region.chars().all(|c| c.is_ascii_uppercase()) {
            Ok(())
        } else {
            Err(format!(
                "{region} is not a two-letter country code; leave it empty for the best available exit"
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PsiphonSnapshot {
    /// "idle", "connecting", "connected", "error".
    pub state: String,
    pub pid: Option<u32>,
    /// The loopback listener, once tunnel-core has bound one. Present while
    /// still connecting, which is exactly why it is not the connected signal.
    pub socks_port: Option<u16>,
    /// The country the connected server is in, as Psiphon reports it.
    pub exit_region: Option<String>,
    /// Every country Psiphon last said it had. Read from its own notice rather
    /// than a table of ours, which would go stale silently.
    pub available_regions: Vec<String>,
    pub last_error: Option<String>,
    pub status_message: Option<String>,
}

impl Default for PsiphonSnapshot {
    fn default() -> Self {
        Self {
            state: "idle".into(),
            pid: None,
            socks_port: None,
            exit_region: None,
            available_regions: Vec::new(),
            last_error: None,
            status_message: None,
        }
    }
}

/// One notice, as tunnel-core writes it.
#[derive(Debug, Deserialize)]
struct Notice {
    #[serde(rename = "noticeType")]
    notice_type: String,
    #[serde(default)]
    data: serde_json::Value,
}

struct Inner {
    child: Mutex<Option<Child>>,
    snapshot: Mutex<PsiphonSnapshot>,
    notices: Mutex<VecDeque<String>>,
    /// Bumped by every start and stop, so a reader or watcher belonging to a
    /// superseded run does nothing rather than writing over the current one.
    generation: AtomicU64,
}

#[derive(Clone)]
pub struct Psiphon {
    inner: Arc<Inner>,
}

impl Default for Psiphon {
    fn default() -> Self {
        Self::new()
    }
}

impl Psiphon {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                child: Mutex::new(None),
                snapshot: Mutex::new(PsiphonSnapshot::default()),
                notices: Mutex::new(VecDeque::with_capacity(MAX_NOTICES)),
                generation: AtomicU64::new(0),
            }),
        }
    }

    pub fn snapshot(&self) -> PsiphonSnapshot {
        lock(&self.inner.snapshot).clone()
    }

    /// This carrier, when it is actually carrying traffic.
    ///
    /// `None` until a tunnel exists, not merely until the listener does -- see
    /// the note on `Tunnels` at the top of this file.
    pub fn carrier(&self) -> Option<Carrier> {
        let snapshot = lock(&self.inner.snapshot);
        if snapshot.state != "connected" {
            return None;
        }
        Some(Carrier {
            kind: CarrierKind::Psiphon,
            socks: SocketAddr::from((Ipv4Addr::LOCALHOST, snapshot.socks_port?)),
            // Psiphon reaches many servers and replaces the one it uses without
            // telling us to re-render anything. There is no single gateway
            // address to exempt from the TUN device, so the process rule in
            // `chain` carries that alone -- which is what it was already doing
            // everywhere.
            endpoint: None,
            // It carries datagrams, but a QUIC handshake through a SOCKS5
            // association is not something this has been measured doing, and
            // claiming it would mark hysteria2 nodes usable on the strength of
            // a guess. Reported false until measured, which costs a label on
            // some nodes and risks nothing.
            carries_quic: false,
        })
    }

    /// The notice stream kept for a diagnostics report.
    ///
    /// Not forwarded to the shared log as it arrives: tunnel-core emitted 499
    /// notices in one measured connect, which would evict the engine's own
    /// entries from a bounded buffer. Kept here and collected only when a
    /// report is being written.
    pub fn notices(&self) -> Vec<String> {
        lock(&self.inner.notices).iter().cloned().collect()
    }

    /// Starts Psiphon and waits for a tunnel.
    ///
    /// Blocking, and returns only once there is something to route into or a
    /// reason there is not. The caller is about to point an interface at this:
    /// a listener with no tunnel behind it swallows packets instead of refusing
    /// them, which is worse for the person using it than an honest failure.
    pub fn start(&self, app: &AppHandle, settings: &PsiphonSettings) -> Result<SocketAddr, String> {
        settings.validate()?;
        self.stop();

        let inner = &self.inner;
        let generation = inner.generation.fetch_add(1, Ordering::SeqCst) + 1;

        let binary = locate(app)?;
        let server_list = locate_server_list(app)?;
        let home = app
            .path()
            .app_data_dir()
            .map_err(|error| format!("no application data directory: {error}"))?
            .join("psiphon");
        std::fs::create_dir_all(&home)
            .map_err(|error| format!("cannot prepare the Psiphon directory: {error}"))?;

        let config_path = home.join("config.json");
        std::fs::write(&config_path, render_config(settings, &home))
            .map_err(|error| format!("cannot write the Psiphon config: {error}"))?;

        {
            let mut snapshot = lock(&inner.snapshot);
            *snapshot = PsiphonSnapshot {
                state: "connecting".into(),
                status_message: Some(match settings.egress_region.trim() {
                    "" => "Finding a way out".into(),
                    region => format!("Finding a way out through {region}"),
                }),
                ..PsiphonSnapshot::default()
            };
        }

        let mut command = Command::new(&binary);
        command
            .arg("-config")
            .arg(&config_path)
            .arg("-serverList")
            .arg(&server_list)
            .arg("-dataRootDirectory")
            .arg(&home)
            .current_dir(&home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        crate::core_supervisor::hide_console(&mut command);

        let mut child = command
            .spawn()
            .map_err(|error| format!("cannot start Psiphon: {error}"))?;
        let pid = child.id();
        let stderr = child.stderr.take();
        let stdout = child.stdout.take();

        {
            // Claimed under the same lock a stop takes, so a stop that landed
            // while this was spawning cannot leave the child running
            // unsupervised.
            let mut guard = lock(&inner.child);
            if inner.generation.load(Ordering::SeqCst) != generation {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Psiphon was stopped while it was starting".into());
            }
            *guard = Some(child);
        }
        lock(&inner.snapshot).pid = Some(pid);

        // The notices are the whole interface, and they arrive on stderr.
        if let Some(stderr) = stderr {
            spawn_notice_reader(app.clone(), inner.clone(), stderr, generation);
        }
        // Nothing is written to stdout, but a piped stream nobody drains is a
        // process that blocks on its own output once the pipe fills.
        if let Some(stdout) = stdout {
            thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    if line.is_err() {
                        break;
                    }
                }
            });
        }

        match self.wait_for_tunnel(generation) {
            Ok(address) => {
                app.state::<CoreSupervisor>().record(
                    "psiphon",
                    "info",
                    format!("Psiphon is carrying traffic; SOCKS listener on {address}"),
                );
                Ok(address)
            }
            Err(error) => {
                // Never leave a half-started carrier behind: the chain would be
                // pointed at a listener with no tunnel under it.
                self.stop();
                let mut snapshot = lock(&inner.snapshot);
                snapshot.state = "error".into();
                snapshot.status_message = None;
                snapshot.last_error = Some(error.clone());
                Err(error)
            }
        }
    }

    /// Waits for `Tunnels` to report at least one, or for the process to die.
    fn wait_for_tunnel(&self, generation: u64) -> Result<SocketAddr, String> {
        let inner = &self.inner;
        let deadline = Instant::now() + ESTABLISH_TIMEOUT;
        while Instant::now() < deadline {
            if inner.generation.load(Ordering::SeqCst) != generation {
                return Err("Psiphon was stopped while it was starting".into());
            }
            {
                let snapshot = lock(&inner.snapshot);
                if snapshot.state == "connected" {
                    if let Some(port) = snapshot.socks_port {
                        return Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
                    }
                }
                if let Some(error) = snapshot.last_error.clone() {
                    return Err(error);
                }
            }
            // The process can exit without ever emitting a failure notice --
            // a missing server list does that. Noticing here is what turns a
            // silent death into a message.
            if let Some(child) = lock(&inner.child).as_mut() {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return Err("Psiphon stopped before it connected".into());
                }
            } else {
                return Err("Psiphon was stopped while it was starting".into());
            }
            thread::sleep(Duration::from_millis(200));
        }
        Err(format!(
            "Psiphon did not find a way out in {}s",
            ESTABLISH_TIMEOUT.as_secs()
        ))
    }

    pub fn stop(&self) {
        let inner = &self.inner;
        inner.generation.fetch_add(1, Ordering::SeqCst);
        if let Some(mut child) = lock(&inner.child).take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let mut snapshot = lock(&inner.snapshot);
        // The regions survive a stop: they describe what Psiphon has, not what
        // this run did, and re-asking would leave the screen with nothing to
        // offer until the next successful connect.
        let regions = std::mem::take(&mut snapshot.available_regions);
        *snapshot = PsiphonSnapshot {
            available_regions: regions,
            ..PsiphonSnapshot::default()
        };
    }
}

impl Drop for Psiphon {
    fn drop(&mut self) {
        // Only the last handle owns the child; the rest are clones held by
        // Tauri state and the readers.
        if Arc::strong_count(&self.inner) == 1 {
            self.stop();
        }
    }
}

/// Reads the notice stream and turns it into state.
fn spawn_notice_reader(
    app: AppHandle,
    inner: Arc<Inner>,
    stderr: std::process::ChildStderr,
    generation: u64,
) {
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            if inner.generation.load(Ordering::SeqCst) != generation {
                return;
            }
            let Ok(line) = line else { break };
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            {
                let mut notices = lock(&inner.notices);
                if notices.len() == MAX_NOTICES {
                    notices.pop_front();
                }
                notices.push_back(line.clone());
            }
            let Ok(notice) = serde_json::from_str::<Notice>(&line) else {
                // Not JSON, so not a notice. Kept above for diagnostics and
                // otherwise ignored rather than treated as a failure: a
                // panic trace or a Go runtime warning is worth having and is
                // not something to act on.
                continue;
            };
            apply_notice(&app, &inner, &notice);
        }
    });
}

/// Applies one notice, and forwards anything worth a line in the shared log.
///
/// Thin on purpose: everything that decides state lives in
/// [`apply_notice_to_snapshot`], which needs no Tauri handle and is therefore
/// the thing the tests exercise. Splitting it this way is not tidiness -- a
/// test that reimplements the logic it is checking passes while production
/// drifts away from it.
fn apply_notice(app: &AppHandle, inner: &Arc<Inner>, notice: &Notice) {
    let reportable = {
        let mut snapshot = lock(&inner.snapshot);
        apply_notice_to_snapshot(&mut snapshot, notice)
    };
    if let Some(message) = reportable {
        app.state::<CoreSupervisor>()
            .record("psiphon", "warn", message);
    }
}

/// Applies one notice to the snapshot, returning anything the user should see.
fn apply_notice_to_snapshot(snapshot: &mut PsiphonSnapshot, notice: &Notice) -> Option<String> {
    match notice.notice_type.as_str() {
        "ListeningSocksProxyPort" => {
            if let Some(port) = notice.data.get("port").and_then(|v| v.as_u64()) {
                snapshot.socks_port = u16::try_from(port).ok();
            }
        }
        "Tunnels" => {
            let count = notice.data.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            // Upstream's comment says "count > 1"; one tunnel is connected, and
            // this is what the notice actually means.
            if count > 0 {
                if snapshot.state != "connected" {
                    snapshot.state = "connected".into();
                    snapshot.status_message = None;
                    snapshot.last_error = None;
                }
            } else if snapshot.state == "connected" {
                // Psiphon reconnects on its own and the listener stays bound
                // throughout, so this is reported rather than acted on --
                // tearing the chain down here would turn a reconnection Psiphon
                // handles into an outage we caused.
                snapshot.state = "connecting".into();
                snapshot.status_message = Some("Reconnecting".into());
            }
        }
        "AvailableEgressRegions" => {
            if let Some(regions) = notice.data.get("regions").and_then(|v| v.as_array()) {
                let mut list: Vec<String> = regions
                    .iter()
                    .filter_map(|value| value.as_str())
                    .filter(|region| region.len() == 2)
                    .map(str::to_string)
                    .collect();
                list.sort();
                snapshot.available_regions = list;
            }
        }
        "ConnectedServerRegion" => {
            snapshot.exit_region = notice
                .data
                .get("serverRegion")
                .and_then(|v| v.as_str())
                .map(str::to_string);
        }
        // Psiphon gave up. It says so before it exits, and the reason is worth
        // far more than the exit itself: measured on a fresh data directory,
        // asking for Japan left 13 candidate servers out of 430 and none of
        // them answered, which is a country with no capacity rather than
        // anything wrong with the network in front of it. Without this the user
        // is told only that the process stopped.
        "EstablishTunnelTimeout" => {
            snapshot.state = "error".into();
            snapshot.status_message = None;
            snapshot.last_error = Some(
                "Psiphon could not reach any server in time. If an exit country is chosen, it \
                 may have no capacity right now -- try Best available, which can use every \
                 server it knows about."
                    .into(),
            );
        }
        // The failures worth surfacing. Everything else is diagnostic and stays
        // in the notice buffer.
        "Alert" | "Error" => {
            return notice
                .data
                .get("message")
                .and_then(|v| v.as_str())
                .map(str::to_string);
        }
        _ => {}
    }
    None
}

/// The config tunnel-core is started with.
///
/// Small on purpose. Every field here is one this app has a reason to set;
/// tunnel-core has dozens more whose defaults are chosen against live censored
/// networks by people who measure them, which is not something to second-guess
/// from here.
fn render_config(settings: &PsiphonSettings, home: &Path) -> String {
    serde_json::json!({
        "PropagationChannelId": PROPAGATION_CHANNEL_ID,
        "SponsorId": SPONSOR_ID,
        // Our own version, as a string, which is what tunnel-core's sample says
        // and what it rejects the config for getting wrong. Reporting one of
        // Psiphon's own client versions would put our sessions in someone
        // else's column.
        "ClientVersion": env!("CARGO_PKG_VERSION").replace('.', ""),
        "DataRootDirectory": home.to_string_lossy(),
        "EgressRegion": settings.egress_region.trim(),
        "EstablishTunnelTimeoutSeconds": ESTABLISH_TUNNEL_TIMEOUT_SECONDS,
        // Zero means "pick a free one and tell me", and the port that comes
        // back is what the chain is configured against. A fixed port is one
        // more thing that can already be taken on a machine we do not control,
        // and that failure would look like Psiphon not starting.
        "LocalSocksProxyPort": 0,
        // Nothing asks for an HTTP proxy, and a listener nobody uses is a
        // listener on loopback that anything on this machine can reach.
        "DisableLocalHTTPProxy": true,
        // Without these a failed establish is a silent one. They stay on this
        // machine unless the user sends a report.
        "EmitDiagnosticNotices": true,
        "EmitDiagnosticNetworkParameters": false,
    })
    .to_string()
}

fn locate(app: &AppHandle) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("WHITEAESTHER_PSIPHON_PATH") {
        if !path.trim().is_empty() {
            candidates.push(PathBuf::from(path));
        }
    }
    if let Ok(resources) = app.path().resource_dir() {
        candidates.push(resources.join(PSIPHON_FILENAME));
        candidates.push(resources.join("binaries").join(PSIPHON_FILENAME));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join(PSIPHON_FILENAME));
        }
    }
    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err("the Psiphon carrier is missing from this installation".into())
}

/// The bootstrap list, which tunnel-core needs to reach anything the first time.
///
/// Its absence is reported here rather than left to the process, which would
/// otherwise spend two minutes dialling an empty list and report only that it
/// could not connect.
fn locate_server_list(app: &AppHandle) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    if let Ok(resources) = app.path().resource_dir() {
        candidates.push(resources.join(SERVER_LIST_FILENAME));
        candidates.push(resources.join("binaries").join(SERVER_LIST_FILENAME));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join(SERVER_LIST_FILENAME));
        }
    }
    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(
        "the Psiphon server list is missing from this installation, so there is nothing to \
         bootstrap from"
            .into(),
    )
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(json: &str) -> Notice {
        serde_json::from_str(json).expect("a notice")
    }

    /// Feeds one notice through the same function production uses.
    fn apply(snapshot: &mut PsiphonSnapshot, json: &str) -> Option<String> {
        apply_notice_to_snapshot(snapshot, &notice(json))
    }

    #[test]
    fn a_listener_without_a_tunnel_is_not_connected() {
        // The trap this carrier shares with tor: the SOCKS port is bound well
        // before anything can be carried through it. Reporting connected here
        // hands the chain a proxy with nowhere to forward to, which swallows
        // packets rather than refusing them.
        let mut snapshot = PsiphonSnapshot::default();
        apply(&mut snapshot, r#"{"noticeType":"ListeningSocksProxyPort","data":{"port":64347}}"#);
        assert_eq!(snapshot.socks_port, Some(64347));
        assert_ne!(snapshot.state, "connected");
    }

    #[test]
    fn one_tunnel_is_connected() {
        // Upstream's own comment says "when count > 1, the core is connected",
        // which is an off-by-one in their documentation. Following it literally
        // would leave a perfectly good single-tunnel session reported as still
        // connecting, forever.
        let mut snapshot = PsiphonSnapshot::default();
        apply(&mut snapshot, r#"{"noticeType":"ListeningSocksProxyPort","data":{"port":64347}}"#);
        apply(&mut snapshot, r#"{"noticeType":"Tunnels","data":{"count":1}}"#);
        assert_eq!(snapshot.state, "connected");
    }

    #[test]
    fn losing_every_tunnel_is_a_reconnect_and_not_a_failure() {
        // Psiphon reconnects on its own and keeps the listener bound while it
        // does. Tearing the chain down here would turn a reconnection it
        // handles into an outage we caused.
        let mut snapshot = PsiphonSnapshot::default();
        apply(&mut snapshot, r#"{"noticeType":"Tunnels","data":{"count":1}}"#);
        apply(&mut snapshot, r#"{"noticeType":"Tunnels","data":{"count":0}}"#);
        assert_eq!(snapshot.state, "connecting");
        assert_eq!(snapshot.status_message.as_deref(), Some("Reconnecting"));
        assert!(snapshot.last_error.is_none(), "a reconnect is not an error");
    }

    #[test]
    fn the_regions_come_from_psiphon_rather_than_from_a_table_of_ours() {
        // Measured: it reported 25. A hardcoded list goes stale silently and
        // offers countries that are no longer there.
        let mut snapshot = PsiphonSnapshot::default();
        apply(
            &mut snapshot,
            r#"{"noticeType":"AvailableEgressRegions","data":{"regions":["US","JP","FR","XYZ",""]}}"#,
        );
        assert_eq!(snapshot.available_regions, vec!["FR", "JP", "US"]);
    }

    #[test]
    fn the_exit_country_is_read_from_the_connected_server() {
        let mut snapshot = PsiphonSnapshot::default();
        apply(&mut snapshot, r#"{"noticeType":"ConnectedServerRegion","data":{"serverRegion":"FR"}}"#);
        assert_eq!(snapshot.exit_region.as_deref(), Some("FR"));
    }

    #[test]
    fn giving_up_names_the_exit_country_as_the_likely_reason() {
        // Measured: a fresh data directory holds 430 bootstrap servers, and
        // asking for Japan narrowed that to 13, none of which answered inside
        // the two-minute establish timeout. The process then exits, and without
        // reading this notice the only thing left to report is that it stopped
        // -- which points at the network rather than at the one setting that
        // actually caused it.
        let mut snapshot = PsiphonSnapshot::default();
        apply(&mut snapshot, r#"{"noticeType":"EstablishTunnelTimeout","data":{"timeout":"2m0s"}}"#);
        assert_eq!(snapshot.state, "error");
        let reason = snapshot.last_error.expect("a reason");
        assert!(reason.contains("exit country"), "{reason}");
        assert!(reason.contains("Best available"), "say what to do instead: {reason}");
    }

    #[test]
    fn a_region_is_either_two_upper_case_letters_or_nothing_at_all() {
        assert!(PsiphonSettings { egress_region: String::new() }.validate().is_ok());
        assert!(PsiphonSettings { egress_region: "JP".into() }.validate().is_ok());
        for bad in ["jp", "JPN", "J", "!!"] {
            assert!(
                PsiphonSettings { egress_region: bad.into() }.validate().is_err(),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn the_config_asks_for_a_chosen_port_and_no_http_listener() {
        let rendered = render_config(
            &PsiphonSettings { egress_region: "JP".into() },
            Path::new("/tmp/psiphon"),
        );
        let config: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        // Zero is "pick one and tell me". A fixed port is one more thing that
        // can already be taken on a machine we do not control.
        assert_eq!(config["LocalSocksProxyPort"], 0);
        assert_eq!(config["DisableLocalHTTPProxy"], true);
        assert_eq!(config["EgressRegion"], "JP");
        // Bounded, because tunnel-core's own default is unlimited -- and an
        // unlimited establish is a carrier that never reports failure.
        assert_eq!(
            config["EstablishTunnelTimeoutSeconds"],
            ESTABLISH_TUNNEL_TIMEOUT_SECONDS
        );
        assert_eq!(config["EmitDiagnosticNotices"], true);
    }

    #[test]
    fn no_exit_country_is_sent_as_empty_rather_than_omitted() {
        // tunnel-core reads a missing EgressRegion and an empty one the same
        // way, but writing it explicitly keeps the config self-describing for
        // anyone reading it out of the data directory during a support call.
        let rendered = render_config(&PsiphonSettings::default(), Path::new("/tmp/psiphon"));
        let config: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(config["EgressRegion"], "");
    }

    #[test]
    fn a_notice_that_is_not_json_never_stops_the_reader() {
        // A Go panic trace or a runtime warning arrives on the same stream.
        // Treating it as a parse failure that ends the loop would take out the
        // only channel this carrier has for reporting anything.
        assert!(serde_json::from_str::<Notice>("panic: runtime error").is_err());
    }
}

/// Whether this build ships the Psiphon carrier and the list it bootstraps from.
///
/// Both are required: the binary without the server list spends two minutes
/// dialling nothing and then reports that it could not connect.
pub fn is_available(app: &AppHandle) -> bool {
    locate(app).is_ok() && locate_server_list(app).is_ok()
}

impl Psiphon {
    /// Whether the child is still running.
    ///
    /// Asked of the process rather than of the snapshot: the notice reader
    /// simply ends when the pipe closes, so a process that died leaves the last
    /// state it reported sitting there looking healthy. Nothing else would ever
    /// notice, and the screen would say connected over a listener that is gone.
    pub fn is_alive(&self) -> bool {
        let mut guard = lock(&self.inner.child);
        match guard.as_mut() {
            Some(child) => !matches!(child.try_wait(), Ok(Some(_))),
            None => false,
        }
    }
}
