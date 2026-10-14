//! Asks the core which gateways are reachable, without connecting to one.
//!
//! The core answers `--scan-only` and `--test-endpoint` with a single JSON
//! object on stdout and exits. Running it as a child rather than linking the
//! engine keeps this crate free of the C++ toolchain BoringSSL needs, and keeps
//! the connection path — which supports protocols the embedded API does not —
//! exactly as it was.

use crate::core_supervisor::{CoreProfile, CoreSupervisor};
use serde::Serialize;
use std::{
    io::Read,
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use tauri::{AppHandle, State};

/// The core's own cap; asking for more is silently reduced, so mirror it here.
const MAX_CANDIDATES: u32 = 64;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCandidate {
    pub peer: String,
    pub rtt_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanOutcome {
    pub candidates: Vec<ScanCandidate>,
    /// Which transport actually produced them, which is not always the one asked for.
    pub transport: String,
    /// Set when the first transport found nothing and the other was swept instead.
    pub fell_back: bool,
}

#[tauri::command]
pub async fn scan_endpoints(
    app: AppHandle,
    supervisor: State<'_, CoreSupervisor>,
    profile: CoreProfile,
    limit: u32,
) -> Result<ScanOutcome, String> {
    supervisor.require_idle("Disconnect before scanning for endpoints")?;
    let inner: CoreSupervisor = (*supervisor).clone();
    let limit = limit.clamp(1, MAX_CANDIDATES);
    tauri::async_runtime::spawn_blocking(move || scan_blocking(&app, &inner, &profile, limit))
        .await
        .map_err(|error| format!("the scan did not finish: {error}"))?
}

#[tauri::command]
pub async fn test_endpoint(
    app: AppHandle,
    supervisor: State<'_, CoreSupervisor>,
    profile: CoreProfile,
    endpoint: String,
) -> Result<ScanCandidate, String> {
    supervisor.require_idle("Disconnect before testing an endpoint")?;
    let inner: CoreSupervisor = (*supervisor).clone();
    tauri::async_runtime::spawn_blocking(move || {
        // The transport the profile is set to, not a fixed one. A gateway can
        // answer over TCP and be unusable over QUIC -- on a network that
        // interferes with UDP, every H3 endpoint fails while H2 succeeds -- so
        // testing the wrong transport reports an endpoint as good that the next
        // connect cannot use.
        let transport = transport_of(&profile);
        let value = run_report(
            &app,
            &inner,
            &profile,
            &["--test-endpoint".into(), endpoint],
            transport,
        )?;
        candidate_from(&value).ok_or_else(|| "the core gave an unreadable answer".to_string())
    })
    .await
    .map_err(|error| format!("the test did not finish: {error}"))?
}

#[tauri::command]
pub fn cancel_scan(supervisor: State<'_, CoreSupervisor>) -> bool {
    supervisor.cancel_scan()
}

/// Which MASQUE transport the profile is set to.
///
/// The scan and the endpoint test both need this: probing over the wrong one
/// answers a question the user did not ask.
fn transport_of(profile: &CoreProfile) -> &'static str {
    if profile.masque_transport == "h2" { "h2" } else { "h3" }
}

fn scan_blocking(
    app: &AppHandle,
    supervisor: &CoreSupervisor,
    profile: &CoreProfile,
    limit: u32,
) -> Result<ScanOutcome, String> {
    let configured = transport_of(profile);
    let args = vec!["--scan-only".to_string(), "--scan-limit".into(), limit.to_string()];

    let first = run_report(app, supervisor, profile, &args, configured)?;
    let candidates = candidates_from(&first);
    if !candidates.is_empty() {
        return Ok(ScanOutcome { candidates, transport: configured.into(), fell_back: false });
    }

    // The prober picks its socket from the transport it is handed: H2 probes
    // over TCP, H3 over QUIC. Scanning only the configured one therefore
    // searches UDP alone on the default profile, and a network that blocks UDP
    // reports an empty internet. Sweep the other before believing that.
    let other = if configured == "h2" { "h3" } else { "h2" };
    let second = run_report(app, supervisor, profile, &args, other)?;
    Ok(ScanOutcome {
        candidates: candidates_from(&second),
        transport: other.into(),
        fell_back: true,
    })
}

/// Runs the core in a reporting mode and returns the JSON object it printed.
fn run_report(
    app: &AppHandle,
    supervisor: &CoreSupervisor,
    profile: &CoreProfile,
    extra: &[String],
    transport: &str,
) -> Result<serde_json::Value, String> {
    profile.validate()?;
    let (core_path, config_dir, identity_path) = crate::core_supervisor::core_paths(app, profile)?;

    let mut command = report_process(&core_path, &config_dir, &identity_path, profile, extra, transport);

    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot run the core: {error}"))?;
    let stdout = child.stdout.take();

    supervisor.hold_scan(child)?;
    let reader = thread::spawn(move || {
        let mut text = String::new();
        if let Some(mut stdout) = stdout {
            let _ = stdout.read_to_string(&mut text);
        }
        text
    });

    // Polled rather than waited on, so a cancel can take the child out from
    // under this loop and kill it.
    loop {
        thread::sleep(Duration::from_millis(150));
        match supervisor.poll_scan() {
            ScanState::Gone => return Err("the scan was cancelled".into()),
            ScanState::Running => continue,
            ScanState::Exited => break,
        }
    }

    let text = reader.join().unwrap_or_default();
    let line = text
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .ok_or_else(|| "the core reported nothing".to_string())?;
    let value: serde_json::Value = serde_json::from_str(line)
        .map_err(|error| format!("the core gave an unreadable answer: {error}"))?;

    if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("the scan failed")
            .to_string());
    }
    Ok(value)
}

fn report_process(core_path: &std::path::Path, config_dir: &std::path::Path, identity_path: &std::path::Path, profile: &CoreProfile, extra: &[String], transport: &str) -> Command {
    let mut command = Command::new(core_path);
    command
        // MASQUE regardless of the profile's protocol: the core's reporting
        // modes wrap scan_embedded, which has no WireGuard or WARP-in-WARP
        // path. The panel says so rather than quietly scanning the wrong thing.
        .arg("--masque")
        .args(["--scan", &profile.scan_mode])
        .args(["--ip", &profile.ip_family])
        .args(["--noize", &profile.noize])
        .args(["--config", &identity_path.to_string_lossy()])
        .args(["--log-level", "warn"])
        .args(["--validate-secs", &profile.validate_secs.to_string()])
        .args(["--startup-secs", &profile.startup_secs.to_string()])
        .args(profile.tls_args())
        .args(extra)
        .current_dir(config_dir)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if transport == "h2" {
        command.arg("--h2");
        if profile.fragment_client_hello {
            command.args(["--fragment", "--fragment-size", &profile.fragment_size, "--fragment-delay", &profile.fragment_delay]);
        }
    }
    if profile.performance_profile != "auto" { command.args(["--perf", &profile.performance_profile]); }
    crate::core_supervisor::set_engine_environment(&mut command, profile);
    crate::core_supervisor::hide_console(&mut command);

    command
}

pub enum ScanState {
    Running,
    Exited,
    /// Taken by a cancel.
    Gone,
}

fn candidates_from(value: &serde_json::Value) -> Vec<ScanCandidate> {
    value
        .get("results")
        .and_then(serde_json::Value::as_array)
        .map(|items| items.iter().filter_map(candidate_from).collect())
        .unwrap_or_default()
}

fn candidate_from(value: &serde_json::Value) -> Option<ScanCandidate> {
    Some(ScanCandidate {
        peer: value.get("peer")?.as_str()?.to_string(),
        rtt_ms: value.get("rttMs")?.as_u64()?,
    })
}

#[cfg(test)]
mod settings_tests {
    use super::*;
    #[test]
    fn scanner_receives_the_sessions_tls_and_private_upstream_settings() {
        let p = CoreProfile { ech: Some("auto".into()), ech_resolver: Some("tcp://1.1.1.1:53".into()), ech_domain: Some("keys.example".into()), tls_groups: Some("X25519:P-256".into()), tls_ciphers: Some("ECDHE-RSA-AES128-GCM-SHA256".into()), disable_grease: true, enroll_address: Some("203.0.113.10:443".into()), upstream_proxy: "socks5://user:secret@127.0.0.1:1080".into(), ..Default::default() };
        let command = report_process(std::path::Path::new("aether"), std::path::Path::new("config"), std::path::Path::new("identity.toml"), &p, &["--scan-only".into()], "h2");
        let args: Vec<_> = command.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        for flag in ["--ech", "--ech-dns", "--ech-domain", "--tls-groups", "--tls-ciphers", "--disable-grease", "--enroll-address", "--fragment"] { assert!(args.iter().any(|a| a == flag), "{flag}"); }
        assert!(args.iter().all(|a| !a.contains("secret")));
        assert!(command.get_envs().any(|(key,value)| key == "AETHER_UPSTREAM" && value.is_some_and(|v| v == p.upstream_proxy.as_str())));
        let off = CoreProfile { ech: Some("off".into()), ..p };
        let command = report_process(std::path::Path::new("aether"), std::path::Path::new("config"), std::path::Path::new("identity.toml"), &off, &[], "h3");
        assert!(!command.get_args().any(|a| a == "--ech-dns" || a == "--ech-domain" || a == "--fragment"));
        assert!(command.get_envs().any(|(key,value)| key == "AETHER_ECH_DNS" && value.is_none()));
    }
}
