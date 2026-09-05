//! Tor as a carrier: three relays, and a SOCKS5 listener at the end of them.
//!
//! The same shape as [`crate::psiphon`] — a supervised child that ends in a
//! listener mihomo routes into — and a different protocol for finding out what
//! it is doing. Tor speaks a line-based control protocol on a loopback port
//! rather than emitting notices, so this authenticates to that port and asks.
//!
//! ## Connected means bootstrapped, not listening
//!
//! The one thing that must not be got wrong here. Tor binds its SOCKS port and
//! opens its control port almost immediately, long before it has a circuit —
//! and a SOCKS listener with no circuit behind it accepts connections and then
//! sits on them. Reporting connected there ships a carrier that says it is
//! working and carries nothing, which on the Android client is exactly how meek
//! passed review and then failed for three minutes straight.
//!
//! So the gate is `GETINFO status/bootstrap-phase` reporting `PROGRESS=100`,
//! and nothing else counts.
//!
//! ## No datagrams, and that is declared rather than discovered
//!
//! Tor carries TCP only. [`CarrierKind::Tor`] says so, which puts `udp: false`
//! on the proxy mihomo dials and a `NETWORK,udp,REJECT` rule above the default
//! route. Both halves matter: a proxy that claims UDP and swallows it is
//! experienced as DNS and QUIC hanging while TCP works, which is the hardest
//! shape of broken to recognise. Refused, a resolver retries over TCP and a
//! browser drops off QUIC, both within a round trip. The chain's own resolvers
//! are DNS-over-HTTPS, so names still resolve throughout.

use std::{
    collections::VecDeque,
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
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

/// How long to wait for a circuit before calling it a failure.
///
/// Generous compared with Psiphon's, and deliberately: a bridge that has to be
/// reached through a pluggable transport routinely takes tens of seconds, and a
/// measured webtunnel circuit on the Android client built in seventeen. Cutting
/// this short would report failure on networks where Tor was going to succeed.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);

/// How often to ask how far along it is.
const BOOTSTRAP_POLL: Duration = Duration::from_millis(500);

/// Long enough for tor to write its control port and cookie files.
const CONTROL_FILE_TIMEOUT: Duration = Duration::from_secs(20);

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(windows)]
const TOR_FILENAME: &str = "tor.exe";
#[cfg(not(windows))]
const TOR_FILENAME: &str = "tor";

#[cfg(windows)]
const LYREBIRD_FILENAME: &str = "lyrebird.exe";
#[cfg(not(windows))]
const LYREBIRD_FILENAME: &str = "lyrebird";

/// How much of tor's own output to keep for a diagnostics report.
const MAX_LINES: usize = 400;

/// Which bridges to use, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BridgeMode {
    /// Straight to the Tor network. Right where Tor is not blocked, and the
    /// fastest path when it works.
    #[default]
    None,
    /// The list Tor ships in `pt_config.json`, alongside the binary it belongs
    /// to. Not a list of ours: one written by hand rots, and two of the three
    /// the Android client first shipped were already unreachable.
    BuiltIn,
    /// Lines the user pasted, from bridges.torproject.org or a friend.
    Custom,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct TorSettings {
    pub bridges: BridgeMode,
    /// Which transport to take from the built-in list: "obfs4", "snowflake" or
    /// "meek".
    pub transport: String,
    /// Bridge lines pasted by hand, one per line. Used when `bridges` is
    /// `Custom`.
    pub custom_bridges: String,
}

impl TorSettings {
    pub(crate) fn validate(&self) -> Result<(), String> {
        match self.bridges {
            BridgeMode::None => Ok(()),
            BridgeMode::BuiltIn => Ok(()),
            BridgeMode::Custom => {
                if self.bridge_lines().is_empty() {
                    Err("paste at least one bridge line, or choose the built-in bridges".into())
                } else {
                    Ok(())
                }
            }
        }
    }

    /// The pasted lines, with blanks and comments dropped.
    ///
    /// `Bridge ` prefixes are stripped: the page people copy from writes them
    /// with the keyword and the torrc line needs it exactly once, so pasting
    /// verbatim would otherwise produce `Bridge Bridge obfs4 ...` and tor would
    /// refuse the file with a parse error naming a line the user did not write.
    fn bridge_lines(&self) -> Vec<String> {
        self.custom_bridges
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                line.strip_prefix("Bridge ")
                    .or_else(|| line.strip_prefix("bridge "))
                    .unwrap_or(line)
                    .trim()
                    .to_string()
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TorSnapshot {
    /// "idle", "connecting", "connected", "error".
    pub state: String,
    pub pid: Option<u32>,
    pub socks_port: Option<u16>,
    /// How far bootstrapping has got, 0-100.
    pub bootstrap: u8,
    /// What tor says it is doing right now, in its own words.
    pub bootstrap_summary: Option<String>,
    pub last_error: Option<String>,
}

impl Default for TorSnapshot {
    fn default() -> Self {
        Self {
            state: "idle".into(),
            pid: None,
            socks_port: None,
            bootstrap: 0,
            bootstrap_summary: None,
            last_error: None,
        }
    }
}

struct Inner {
    child: Mutex<Option<Child>>,
    snapshot: Mutex<TorSnapshot>,
    lines: Mutex<VecDeque<String>>,
    generation: AtomicU64,
}

#[derive(Clone)]
pub struct Tor {
    inner: Arc<Inner>,
}

impl Default for Tor {
    fn default() -> Self {
        Self::new()
    }
}

impl Tor {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                child: Mutex::new(None),
                snapshot: Mutex::new(TorSnapshot::default()),
                lines: Mutex::new(VecDeque::with_capacity(MAX_LINES)),
                generation: AtomicU64::new(0),
            }),
        }
    }

    pub fn snapshot(&self) -> TorSnapshot {
        lock(&self.inner.snapshot).clone()
    }

    /// This carrier, when it is actually carrying traffic.
    ///
    /// `None` until bootstrap reaches 100. See the note at the top of this
    /// file: a listening SOCKS port is not a circuit.
    pub fn carrier(&self) -> Option<Carrier> {
        let snapshot = lock(&self.inner.snapshot);
        if snapshot.state != "connected" {
            return None;
        }
        Some(Carrier {
            kind: CarrierKind::Tor,
            socks: SocketAddr::from((Ipv4Addr::LOCALHOST, snapshot.socks_port?)),
            // Tor reaches the network through a guard that changes on its own
            // schedule, so there is no one address to exempt from the TUN
            // device; the process rule in `chain` carries that alone.
            endpoint: None,
            // Tor carries no datagrams at all, so it certainly carries no QUIC.
            carries_quic: false,
        })
    }

    pub fn lines(&self) -> Vec<String> {
        lock(&self.inner.lines).iter().cloned().collect()
    }

    /// Starts tor and waits for a circuit.
    pub fn start(&self, app: &AppHandle, settings: &TorSettings) -> Result<SocketAddr, String> {
        settings.validate()?;
        self.stop();

        let inner = &self.inner;
        let generation = inner.generation.fetch_add(1, Ordering::SeqCst) + 1;

        let binary = locate(app, TOR_FILENAME, &[])?;
        let support = support_dir(app)?;
        let home = app
            .path()
            .app_data_dir()
            .map_err(|error| format!("no application data directory: {error}"))?
            .join("tor");
        // Tor refuses to start if its data directory is group or world
        // readable, which is a check worth keeping rather than working around.
        std::fs::create_dir_all(&home)
            .map_err(|error| format!("cannot prepare the Tor directory: {error}"))?;

        let control_port_file = home.join("control-port");
        let cookie_file = home.join("control-auth-cookie");
        // Stale files from a previous run would be read as this run's, and the
        // port in them points at a tor that is no longer there.
        let _ = std::fs::remove_file(&control_port_file);
        let _ = std::fs::remove_file(&cookie_file);

        let torrc = home.join("torrc");
        std::fs::write(
            &torrc,
            render_torrc(settings, &home, &support, &control_port_file, &cookie_file)?,
        )
        .map_err(|error| format!("cannot write the Tor configuration: {error}"))?;

        {
            let mut snapshot = lock(&inner.snapshot);
            *snapshot = TorSnapshot {
                state: "connecting".into(),
                bootstrap_summary: Some("Starting Tor".into()),
                ..TorSnapshot::default()
            };
        }

        let mut command = Command::new(&binary);
        command
            .arg("-f")
            .arg(&torrc)
            .current_dir(&home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        crate::core_supervisor::hide_console(&mut command);

        let mut child = command
            .spawn()
            .map_err(|error| format!("cannot start Tor: {error}"))?;
        let pid = child.id();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        {
            let mut guard = lock(&inner.child);
            if inner.generation.load(Ordering::SeqCst) != generation {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Tor was stopped while it was starting".into());
            }
            *guard = Some(child);
        }
        lock(&inner.snapshot).pid = Some(pid);

        // Both streams drained, or tor blocks on its own logging once a pipe
        // fills -- and its log is the only account of a failure that happens
        // before the control port is up.
        for reader in [
            stdout.map(|out| Box::new(out) as Box<dyn Read + Send>),
            stderr.map(|err| Box::new(err) as Box<dyn Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            spawn_log_reader(app.clone(), inner.clone(), reader, generation);
        }

        match self.wait_for_circuit(&control_port_file, &cookie_file, generation) {
            Ok(address) => {
                app.state::<CoreSupervisor>().record(
                    "tor",
                    "info",
                    format!("Tor has a circuit; SOCKS listener on {address}"),
                );
                Ok(address)
            }
            Err(error) => {
                self.stop();
                let mut snapshot = lock(&inner.snapshot);
                snapshot.state = "error".into();
                snapshot.last_error = Some(error.clone());
                Err(error)
            }
        }
    }

    /// Waits for `PROGRESS=100`, reporting how far it has got along the way.
    fn wait_for_circuit(
        &self,
        control_port_file: &Path,
        cookie_file: &Path,
        generation: u64,
    ) -> Result<SocketAddr, String> {
        let inner = &self.inner;
        let control = read_control_port(control_port_file, CONTROL_FILE_TIMEOUT)?;
        let cookie = read_cookie(cookie_file, CONTROL_FILE_TIMEOUT)?;
        let mut session = ControlSession::open(control, &cookie)?;

        let deadline = Instant::now() + BOOTSTRAP_TIMEOUT;
        while Instant::now() < deadline {
            if inner.generation.load(Ordering::SeqCst) != generation {
                return Err("Tor was stopped while it was starting".into());
            }
            // A tor that died before bootstrapping leaves the control socket
            // closed; noticing here turns a hang into a message.
            if let Some(child) = lock(&inner.child).as_mut() {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return Err("Tor stopped before it built a circuit".into());
                }
            } else {
                return Err("Tor was stopped while it was starting".into());
            }

            let phase = session.get_info("status/bootstrap-phase")?;
            let progress = parse_progress(&phase).unwrap_or(0);
            let summary = parse_summary(&phase);
            {
                let mut snapshot = lock(&inner.snapshot);
                snapshot.bootstrap = progress;
                snapshot.bootstrap_summary = summary.clone();
            }

            if progress >= 100 {
                let port = session.socks_port()?;
                let mut snapshot = lock(&inner.snapshot);
                snapshot.socks_port = Some(port);
                snapshot.state = "connected".into();
                snapshot.bootstrap = 100;
                return Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
            }
            thread::sleep(BOOTSTRAP_POLL);
        }

        let reached = lock(&inner.snapshot).bootstrap;
        Err(format!(
            "Tor did not build a circuit in {}s; it reached {reached}%. \
             If this network blocks Tor, turn bridges on.",
            BOOTSTRAP_TIMEOUT.as_secs()
        ))
    }

    pub fn stop(&self) {
        let inner = &self.inner;
        inner.generation.fetch_add(1, Ordering::SeqCst);
        if let Some(mut child) = lock(&inner.child).take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        *lock(&inner.snapshot) = TorSnapshot::default();
    }
}

impl Drop for Tor {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.stop();
        }
    }
}

/// One authenticated conversation with tor's control port.
struct ControlSession {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

impl ControlSession {
    fn open(control: SocketAddr, cookie: &[u8]) -> Result<Self, String> {
        let stream = TcpStream::connect_timeout(&control, CONTROL_TIMEOUT)
            .map_err(|error| format!("cannot reach the Tor control port: {error}"))?;
        stream
            .set_read_timeout(Some(CONTROL_TIMEOUT))
            .map_err(|error| format!("cannot configure the Tor control port: {error}"))?;
        let reader = BufReader::new(
            stream
                .try_clone()
                .map_err(|error| format!("cannot read the Tor control port: {error}"))?,
        );
        let mut session = Self { stream, reader };

        // Cookie authentication rather than a password: tor writes a file only
        // this user can read, and we prove we read it. A password would have to
        // be generated, written to the torrc in a hashed form and held here in
        // plaintext, which is more moving parts for no more safety.
        let hex: String = cookie.iter().map(|byte| format!("{byte:02x}")).collect();
        let reply = session.command(&format!("AUTHENTICATE {hex}"))?;
        if !reply.starts_with("250") {
            return Err(format!("the Tor control port refused authentication: {reply}"));
        }
        Ok(session)
    }

    fn command(&mut self, line: &str) -> Result<String, String> {
        self.stream
            .write_all(format!("{line}\r\n").as_bytes())
            .map_err(|error| format!("cannot write to the Tor control port: {error}"))?;
        self.read_reply()
    }

    /// Reads one reply, which may be several lines.
    ///
    /// The protocol marks continuation with `-` or `+` after the code and the
    /// final line with a space, so reading a single line would take the first
    /// line of a multi-line answer and leave the rest to be misread as the
    /// reply to the next command.
    fn read_reply(&mut self) -> Result<String, String> {
        let mut reply = String::new();
        loop {
            let mut line = String::new();
            let read = self
                .reader
                .read_line(&mut line)
                .map_err(|error| format!("cannot read the Tor control port: {error}"))?;
            if read == 0 {
                return Err("the Tor control port closed".into());
            }
            reply.push_str(&line);
            let trimmed = line.trim_end();
            // "250 OK" ends it; "250-..." and "250+..." do not.
            if trimmed.len() >= 4 && trimmed.as_bytes()[3] == b' ' {
                return Ok(reply.trim_end().to_string());
            }
            if trimmed.len() < 4 {
                return Ok(reply.trim_end().to_string());
            }
        }
    }

    fn get_info(&mut self, key: &str) -> Result<String, String> {
        let reply = self.command(&format!("GETINFO {key}"))?;
        if !reply.starts_with("250") {
            return Err(format!("Tor refused GETINFO {key}: {reply}"));
        }
        Ok(reply)
    }

    /// The port tor actually bound, asked for rather than assumed.
    ///
    /// `SocksPort auto` means tor picks one, which is what stops a fixed port
    /// from colliding with whatever else is already on this machine -- so the
    /// only way to know it is to ask.
    fn socks_port(&mut self) -> Result<u16, String> {
        let reply = self.get_info("net/listeners/socks")?;
        // 250-net/listeners/socks="127.0.0.1:9150"
        let quoted = reply
            .split('"')
            .nth(1)
            .ok_or("Tor did not report a SOCKS listener")?;
        quoted
            .rsplit(':')
            .next()
            .and_then(|port| port.parse().ok())
            .ok_or_else(|| format!("Tor reported a SOCKS listener we cannot read: {quoted}"))
    }
}

/// The configuration tor is started with.
fn render_torrc(
    settings: &TorSettings,
    home: &Path,
    support: &Path,
    control_port_file: &Path,
    cookie_file: &Path,
) -> Result<String, String> {
    let mut config = String::new();
    // Both auto: a fixed port is one more thing that can already be taken on a
    // machine we do not control, and that failure looks like Tor not starting.
    config.push_str("SocksPort auto\n");
    config.push_str("ControlPort auto\n");
    config.push_str(&format!(
        "ControlPortWriteToFile {}\n",
        quote(control_port_file)
    ));
    config.push_str("CookieAuthentication 1\n");
    config.push_str(&format!("CookieAuthFile {}\n", quote(cookie_file)));
    config.push_str(&format!("DataDirectory {}\n", quote(home)));
    config.push_str(&format!("GeoIPFile {}\n", quote(&support.join("geoip"))));
    config.push_str(&format!("GeoIPv6File {}\n", quote(&support.join("geoip6"))));
    // Everything on loopback, like mihomo's controller.
    config.push_str("SocksPolicy accept 127.0.0.0/8\n");
    config.push_str("SocksPolicy reject *\n");
    // Without this tor keeps running after the process that started it dies,
    // which on a crash leaves a tunnel nothing is routed into.
    config.push_str("__OwningControllerProcess ");
    config.push_str(&std::process::id().to_string());
    config.push('\n');

    if settings.bridges != BridgeMode::None {
        let lyrebird = support.join(LYREBIRD_FILENAME);
        if !lyrebird.is_file() {
            return Err("the pluggable transports are missing from this installation".into());
        }
        // A normal tor launches its own transports. The Android client had to
        // do the managed-proxy handshake by hand because Guardian Project's JNI
        // build aborts on `exec`; nothing here has that problem, and porting
        // that machinery would be work for a bug we do not have.
        config.push_str(&format!(
            "ClientTransportPlugin meek_lite,obfs4,webtunnel,snowflake exec {}\n",
            quote(&lyrebird)
        ));
        config.push_str("UseBridges 1\n");
        for line in bridge_lines(settings, support)? {
            config.push_str(&format!("Bridge {line}\n"));
        }
    }
    Ok(config)
}

/// The bridges to write into the torrc.
fn bridge_lines(settings: &TorSettings, support: &Path) -> Result<Vec<String>, String> {
    match settings.bridges {
        BridgeMode::None => Ok(Vec::new()),
        BridgeMode::Custom => Ok(settings.bridge_lines()),
        BridgeMode::BuiltIn => {
            let transport = match settings.transport.trim() {
                "" => "obfs4",
                other => other,
            };
            let lines = built_in_bridges(&support.join("pt_config.json"), transport)?;
            if lines.is_empty() {
                return Err(format!(
                    "this build ships no built-in {transport} bridges; paste one instead"
                ));
            }
            Ok(lines)
        }
    }
}

/// Tor's own built-in bridges, read from the file that ships beside the binary.
///
/// Deliberately not a list of ours. One written by hand rots: the first list
/// the Android client shipped was written from memory and two of its three
/// bridges were already unreachable from an uncensored network. This one is
/// maintained by Tor, travels with the binary it belongs to, and is covered by
/// the same signed digest the staging script already checks.
fn built_in_bridges(path: &Path, transport: &str) -> Result<Vec<String>, String> {
    let body = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read the built-in bridges: {error}"))?;
    let config: serde_json::Value = serde_json::from_str(&body)
        .map_err(|error| format!("the built-in bridge list is unreadable: {error}"))?;
    Ok(config
        .get("bridges")
        .and_then(|bridges| bridges.get(transport))
        .and_then(|list| list.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|value| value.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default())
}

/// A path as torrc wants it.
///
/// Quoted, with backslashes doubled: a Windows path is full of them and tor
/// reads a backslash in a quoted value as an escape, so `C:\Users\...` becomes
/// a path with control characters in it and tor refuses the file.
fn quote(path: &Path) -> String {
    format!("\"{}\"", path.to_string_lossy().replace('\\', "\\\\"))
}

fn read_control_port(path: &Path, timeout: Duration) -> Result<SocketAddr, String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(body) = std::fs::read_to_string(path) {
            // PORT=127.0.0.1:51234
            if let Some(address) = body.trim().strip_prefix("PORT=") {
                if let Ok(parsed) = address.trim().parse() {
                    return Ok(parsed);
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("Tor never reported a control port".into())
}

fn read_cookie(path: &Path, timeout: Duration) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(bytes) = std::fs::read(path) {
            if !bytes.is_empty() {
                return Ok(bytes);
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("Tor never wrote its control cookie".into())
}

/// `NOTICE BOOTSTRAP PROGRESS=25 TAG=... SUMMARY="Loading..."`
fn parse_progress(phase: &str) -> Option<u8> {
    phase
        .split("PROGRESS=")
        .nth(1)?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

fn parse_summary(phase: &str) -> Option<String> {
    phase.split("SUMMARY=\"").nth(1)?.split('"').next().map(str::to_string)
}

fn spawn_log_reader(
    app: AppHandle,
    inner: Arc<Inner>,
    reader: Box<dyn Read + Send>,
    generation: u64,
) {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            if inner.generation.load(Ordering::SeqCst) != generation {
                return;
            }
            let Ok(line) = line else { break };
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            {
                let mut lines = lock(&inner.lines);
                if lines.len() == MAX_LINES {
                    lines.pop_front();
                }
                lines.push_back(line.clone());
            }
            // Only the ones worth a person's attention reach the shared log.
            // Tor is chatty while bootstrapping and would evict the engine's
            // own entries from a bounded buffer.
            if line.contains("[warn]") || line.contains("[err]") {
                let level = if line.contains("[err]") { "error" } else { "warn" };
                app.state::<CoreSupervisor>().record("tor", level, line);
            }
        }
    });
}

fn support_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    if let Ok(resources) = app.path().resource_dir() {
        candidates.push(resources.join("tor"));
        candidates.push(resources.join("binaries").join("tor"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("tor"));
        }
    }
    for candidate in candidates {
        if candidate.join("geoip").is_file() {
            return Ok(candidate);
        }
    }
    Err("the Tor support files are missing from this installation".into())
}

fn locate(app: &AppHandle, filename: &str, extra: &[PathBuf]) -> Result<PathBuf, String> {
    let mut candidates = extra.to_vec();
    if let Ok(path) = std::env::var("WHITEAESTHER_TOR_PATH") {
        if !path.trim().is_empty() {
            candidates.push(PathBuf::from(path));
        }
    }
    if let Ok(resources) = app.path().resource_dir() {
        candidates.push(resources.join(filename));
        candidates.push(resources.join("binaries").join(filename));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join(filename));
        }
    }
    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err("the Tor carrier is missing from this installation".into())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_progress_and_summary_are_read_from_the_control_reply() {
        let phase = "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=25 TAG=loading_status \
                     SUMMARY=\"Loading networkstatus consensus\"";
        assert_eq!(parse_progress(phase), Some(25));
        assert_eq!(
            parse_summary(phase).as_deref(),
            Some("Loading networkstatus consensus")
        );
    }

    #[test]
    fn only_a_hundred_per_cent_counts_as_a_circuit() {
        // The trap this carrier exists around: tor binds its SOCKS port almost
        // at once and reports progress for a long time afterwards. Anything
        // below 100 is a listener with nothing behind it, which accepts
        // connections and then sits on them -- a carrier that says it works and
        // carries nothing.
        for progress in [0u8, 5, 25, 80, 99] {
            let phase = format!("250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS={progress}");
            assert!(parse_progress(&phase).unwrap() < 100, "{progress}");
        }
        let done = "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"";
        assert_eq!(parse_progress(done), Some(100));
    }

    #[test]
    fn a_pasted_bridge_keeps_its_keyword_from_being_doubled() {
        // The page people copy from writes "Bridge obfs4 ...", and the torrc
        // needs the keyword exactly once. Pasted verbatim without this, tor
        // refuses the whole file with a parse error naming a line the user
        // never wrote.
        let settings = TorSettings {
            bridges: BridgeMode::Custom,
            transport: String::new(),
            custom_bridges: "Bridge obfs4 1.2.3.4:443 ABC cert=x iat-mode=0\n\
                             obfs4 5.6.7.8:443 DEF cert=y iat-mode=0\n\
                             \n\
                             # a comment\n"
                .into(),
        };
        let lines = settings.bridge_lines();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].starts_with("obfs4 1.2.3.4"), "{lines:?}");
        assert!(lines[1].starts_with("obfs4 5.6.7.8"), "{lines:?}");
    }

    #[test]
    fn choosing_custom_bridges_without_pasting_any_is_refused() {
        // Otherwise tor starts with UseBridges 1 and no bridge, which it treats
        // as a configuration error and reports in a way nobody would connect
        // back to an empty text box.
        let settings = TorSettings {
            bridges: BridgeMode::Custom,
            transport: String::new(),
            custom_bridges: "  \n # nothing but a comment\n".into(),
        };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn windows_paths_survive_the_torrc() {
        // tor reads a backslash inside a quoted value as an escape, so an
        // unescaped Windows path becomes one with control characters in it and
        // the file is refused.
        let quoted = quote(Path::new(r"C:\Users\someone\AppData\tor"));
        assert_eq!(quoted, "\"C:\\\\Users\\\\someone\\\\AppData\\\\tor\"");
    }

    #[test]
    fn the_built_in_bridges_come_from_tors_own_file() {
        // Not a list of ours. The one the Android client wrote by hand had two
        // of its three bridges already unreachable before it shipped.
        let file = std::env::temp_dir().join("whiteaesther-pt-config-test.json");
        std::fs::write(
            &file,
            r#"{"bridges":{"obfs4":["obfs4 1.2.3.4:443 A cert=x"],"snowflake":["snowflake 192.0.2.3:80 B"]}}"#,
        )
        .unwrap();
        assert_eq!(built_in_bridges(&file, "obfs4").unwrap().len(), 1);
        assert_eq!(built_in_bridges(&file, "snowflake").unwrap().len(), 1);
        // A transport the file does not carry is empty rather than an error
        // here; the caller turns that into a message naming the transport.
        assert!(built_in_bridges(&file, "conjure").unwrap().is_empty());
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn a_socks_listener_is_read_from_what_tor_reports_rather_than_assumed() {
        // SocksPort auto means tor picks one, which is what stops a fixed port
        // colliding with whatever else is on the machine.
        let reply = "250-net/listeners/socks=\"127.0.0.1:51234\"\r\n250 OK";
        let quoted = reply.split('"').nth(1).unwrap();
        let port: u16 = quoted.rsplit(':').next().unwrap().parse().unwrap();
        assert_eq!(port, 51234);
    }

    #[test]
    fn no_bridges_means_no_transport_plugin_line() {
        // A ClientTransportPlugin naming a binary we did not ship would stop
        // tor from starting at all, so it appears only when bridges do.
        let home = Path::new("/tmp/tor");
        let support = Path::new("/tmp/support");
        let config = render_torrc(
            &TorSettings::default(),
            home,
            support,
            Path::new("/tmp/tor/control-port"),
            Path::new("/tmp/tor/cookie"),
        )
        .unwrap();
        assert!(!config.contains("ClientTransportPlugin"), "{config}");
        assert!(!config.contains("UseBridges"), "{config}");
        // The things that must always be there.
        assert!(config.contains("SocksPort auto"), "{config}");
        assert!(config.contains("CookieAuthentication 1"), "{config}");
        assert!(config.contains("SocksPolicy reject *"), "{config}");
        assert!(config.contains("__OwningControllerProcess"), "{config}");
    }
}

/// Whether this build actually ships the Tor carrier.
///
/// Tor publishes no expert bundle for `windows-aarch64` or `linux-aarch64`, so
/// a build for those targets has everything except this. The screen reads this
/// rather than offering a carrier that cannot start -- a control that saves and
/// does nothing is worse than one that is absent.
pub fn is_available(app: &AppHandle) -> bool {
    locate(app, TOR_FILENAME, &[]).is_ok() && support_dir(app).is_ok()
}

impl Tor {
    /// Whether the child is still running. See the note on the Psiphon one:
    /// a dead process leaves a healthy-looking snapshot behind it.
    pub fn is_alive(&self) -> bool {
        let mut guard = lock(&self.inner.child);
        match guard.as_mut() {
            Some(child) => !matches!(child.try_wait(), Ok(Some(_))),
            None => false,
        }
    }
}
