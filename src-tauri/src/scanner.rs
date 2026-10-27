//! Multi-profile discovery with independent traffic confirmations.
use crate::{
    core_supervisor::{CoreProfile, CoreSupervisor},
    recovery::{self, EngineRecipe},
};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Manager, State};
const MAX_CANDIDATES: u32 = 24;
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCandidate {
    pub peer: String,
    pub rtt_ms: u64,
    #[serde(default)]
    pub recipe: Option<EngineRecipe>,
    #[serde(default)]
    pub successful_checks: u32,
    #[serde(default)]
    pub attempted_checks: u32,
    #[serde(default)]
    pub jitter_ms: u64,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanOutcome {
    pub candidates: Vec<ScanCandidate>,
    pub transport: String,
    pub fell_back: bool,
    pub diagnostics: Vec<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeAction {
    Scan,
    Confirm,
}
fn rank(candidates: &mut Vec<ScanCandidate>, limit: usize) {
    candidates.sort_by_key(|c| {
        (
            std::cmp::Reverse(c.successful_checks),
            c.attempted_checks.saturating_sub(c.successful_checks),
            c.jitter_ms,
            c.rtt_ms,
        )
    });
    candidates.truncate(limit);
}
fn discover_with<F, C>(
    p: &CoreProfile,
    limit: usize,
    budget: Duration,
    remembered: Vec<ScanCandidate>,
    mut probe: F,
    can_continue: C,
) -> Result<ScanOutcome, String>
where
    F: FnMut(&CoreProfile, ProbeAction, Duration) -> Result<Vec<ScanCandidate>, String>,
    C: Fn() -> bool,
{
    let started = Instant::now();
    let mut candidates = Vec::new();
    let mut diagnostics = Vec::new();
    let mut recipes = recovery::recipes(p, None, None)
        .into_iter()
        .filter(|r| r.protocol == "masque")
        .collect::<Vec<_>>();
    let mut deep_h3 = EngineRecipe::from_profile(p);
    deep_h3.protocol = "masque".into();
    deep_h3.masque_transport = "h3".into();
    deep_h3.scan_mode = "balanced".into();
    if !recipes.contains(&deep_h3) {
        recipes.push(deep_h3);
    }
    let target = limit.clamp(1, 3);
    // Hints must be confirmed on the present network before they become results.
    let mut passes = remembered
        .into_iter()
        .filter(|c| c.recipe.as_ref().is_some_and(|r| recipes.contains(r)))
        .take(3)
        .map(|c| (c.recipe.clone().unwrap(), Some(c)))
        .collect::<Vec<_>>();
    passes.extend(recipes.into_iter().map(|r| (r, None)));
    for (recipe, hint) in passes {
        if !can_continue() {
            return Err("endpoint discovery cancelled or network changed".into());
        }
        if started.elapsed() >= budget
            || candidates
                .iter()
                .filter(|c: &&ScanCandidate| c.successful_checks == 2)
                .count()
                >= target
        {
            break;
        }
        let mut profile = recipe.apply(p);
        profile.peer = None;
        profile.h2_peer = None;
        profile.endpoint_mode = "automatic".into();
        let left = budget.saturating_sub(started.elapsed());
        let hits = if let Some(hint) = hint {
            vec![hint]
        } else {
            match probe(
                &profile,
                ProbeAction::Scan,
                left.min(Duration::from_secs(if recipe.scan_mode == "balanced" {
                    60
                } else {
                    18
                })),
            ) {
                Ok(hits) => hits,
                Err(error) => {
                    if recovery::conclusive_identity_error(&error) {
                        return Err(error);
                    }
                    diagnostics.push(format!("{}: {error}", recipe.label()));
                    continue;
                }
            }
        };
        for mut hit in hits.into_iter().take(2) {
            hit.recipe = Some(recipe.clone());
            hit.successful_checks = 0;
            hit.attempted_checks = 0;
            profile.peer = Some(hit.peer.clone());
            profile.endpoint_mode = "custom-only".into();
            profile.scan_mode = "ironclad".into();
            let mut samples = Vec::new();
            for _ in 0..2 {
                if !can_continue() {
                    return Err("endpoint discovery cancelled or network changed".into());
                }
                if started.elapsed() >= budget {
                    break;
                }
                hit.attempted_checks += 1;
                match probe(
                    &profile,
                    ProbeAction::Confirm,
                    budget
                        .saturating_sub(started.elapsed())
                        .min(Duration::from_secs(25)),
                ) {
                    Ok(result) => {
                        if let Some(c) = result.first() {
                            samples.push(c.rtt_ms);
                        }
                    }
                    Err(error) => {
                        if recovery::conclusive_identity_error(&error) {
                            return Err(error);
                        }
                        diagnostics
                            .push(format!("{} traffic confirmation: {error}", recipe.label()));
                    }
                }
            }
            samples.sort_unstable();
            hit.successful_checks = samples.len() as u32;
            if let (Some(first), Some(last)) = (samples.first(), samples.last()) {
                hit.rtt_ms = first + (last - first) / 2;
                hit.jitter_ms = last - first;
            }
            if hit.successful_checks > 0 {
                candidates.retain(|c: &ScanCandidate| c.peer != hit.peer || c.recipe != hit.recipe);
                candidates.push(hit);
            } else if hit.attempted_checks == 0 {
                diagnostics.push(format!(
                    "{}: traffic confirmation budget expired",
                    recipe.label()
                ));
            }
        }
    }
    rank(&mut candidates, limit);
    let transport = candidates
        .first()
        .and_then(|c| c.recipe.as_ref())
        .map(|r| r.masque_transport.clone())
        .unwrap_or_else(|| p.masque_transport.clone());
    Ok(ScanOutcome {
        fell_back: transport != p.masque_transport,
        transport,
        candidates,
        diagnostics,
    })
}
#[tauri::command]
pub async fn scan_endpoints(
    app: AppHandle,
    supervisor: State<'_, CoreSupervisor>,
    profile: CoreProfile,
    limit: u32,
) -> Result<ScanOutcome, String> {
    let stop = supervisor.begin_search()?;
    supervisor.show_search(true, Some("Finding and confirming gateways".into()));
    let inner = supervisor.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let result = scan_blocking(
            &app,
            &inner,
            &profile,
            limit.clamp(1, MAX_CANDIDATES) as usize,
            &stop,
        );
        inner.stop_scan_process();
        inner.finish_search(&stop);
        result
    })
    .await
    .map_err(|e| format!("the scan did not finish: {e}"))?
}
#[tauri::command]
pub async fn test_endpoint(
    app: AppHandle,
    supervisor: State<'_, CoreSupervisor>,
    profile: CoreProfile,
    endpoint: String,
) -> Result<ScanCandidate, String> {
    let stop = supervisor.begin_search()?;
    supervisor.show_search(true, Some("Confirming the gateway".into()));
    let inner = supervisor.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut profile = profile;
        profile.scan_mode = "ironclad".into();
        let result = run_report(
            &app,
            &inner,
            &profile,
            &["--test-endpoint".into(), endpoint],
            Duration::from_secs(25),
            &stop,
        )
        .and_then(|v| candidate_from(&v).ok_or_else(|| "unreadable endpoint answer".into()));
        inner.stop_scan_process();
        inner.finish_search(&stop);
        result
    })
    .await
    .map_err(|e| format!("the test did not finish: {e}"))?
}
#[tauri::command]
pub fn cancel_scan(supervisor: State<'_, CoreSupervisor>) -> bool {
    supervisor.cancel_scan()
}
fn scan_blocking(
    app: &AppHandle,
    supervisor: &CoreSupervisor,
    p: &CoreProfile,
    limit: usize,
    stop: &AtomicBool,
) -> Result<ScanOutcome, String> {
    let network = crate::route_memory::current_network();
    let context = recovery::context(p);
    let memory_path = app
        .path()
        .app_config_dir()
        .ok()
        .map(|p| p.join("endpoint-memory.json"));
    let key = format!("{}:{context}", network.as_deref().unwrap_or("unknown"));
    let mut memory: std::collections::BTreeMap<String, (u64, Vec<ScanCandidate>)> = memory_path
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let now = crate::route_memory::now_unix();
    memory
        .retain(|_, (at, _)| now.saturating_sub(*at) < crate::route_memory::FORGET_AFTER.as_secs());
    let hints = if network.is_some() {
        memory.get(&key).map(|(_, c)| c.clone()).unwrap_or_default()
    } else {
        Vec::new()
    };
    // Provision once, before a handshake failure can become another registration.
    run_report(
        app,
        supervisor,
        p,
        &["--provision-only".into()],
        Duration::from_secs(120),
        stop,
    )?;
    let budget = Duration::from_secs(match p.scan_mode.as_str() {
        "turbo" => 60,
        "thorough" => 360,
        _ => 210,
    });
    let outcome = discover_with(
        p,
        limit,
        budget,
        hints,
        |profile, action, budget| {
            let extra = match action {
                ProbeAction::Scan => vec![
                    "--scan-only".into(),
                    "--scan-limit".into(),
                    limit.to_string(),
                ],
                ProbeAction::Confirm => vec![
                    "--test-endpoint".into(),
                    profile.peer.clone().ok_or("confirmation has no endpoint")?,
                ],
            };
            let value = run_report(app, supervisor, profile, &extra, budget, stop)?;
            Ok(if action == ProbeAction::Confirm {
                candidate_from(&value).into_iter().collect()
            } else {
                candidates_from(&value)
            })
        },
        || !stop.load(Ordering::SeqCst) && crate::route_memory::current_network() == network,
    )?;
    if network.is_some() {
        memory.insert(
            key,
            (
                now,
                outcome
                    .candidates
                    .iter()
                    .filter(|c| c.successful_checks > 0)
                    .take(8)
                    .cloned()
                    .collect(),
            ),
        );
        while memory.len() > 32 {
            if let Some(old) = memory
                .iter()
                .min_by_key(|(_, v)| v.0)
                .map(|(k, _)| k.clone())
            {
                memory.remove(&old);
            }
        }
        if let Some(path) = memory_path {
            if let Ok(bytes) = serde_json::to_vec(&memory) {
                let staging = path.with_extension("json.tmp");
                if std::fs::write(&staging, bytes).is_ok() {
                    let _ = std::fs::rename(staging, path);
                }
            }
        }
    }
    Ok(outcome)
}
fn run_report(
    app: &AppHandle,
    supervisor: &CoreSupervisor,
    p: &CoreProfile,
    extra: &[String],
    budget: Duration,
    stop: &AtomicBool,
) -> Result<serde_json::Value, String> {
    if stop.load(Ordering::SeqCst) {
        return Err("scan cancelled".into());
    }
    p.validate()?;
    let (core_path, config_dir, identity_path) = crate::core_supervisor::core_paths(app, p)?;
    let mut command = report_process(
        &core_path,
        &config_dir,
        &identity_path,
        p,
        extra,
        &p.masque_transport,
    );
    command.args(["--scan-budget-ms", &budget.as_millis().to_string()]);
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot run core: {e}"))?;
    let stdout = child.stdout.take();
    supervisor.hold_scan(child)?;
    let reader = thread::spawn(move || {
        let mut text = String::new();
        if let Some(mut stdout) = stdout {
            let _ = stdout.read_to_string(&mut text);
        }
        text
    });
    let started = Instant::now();
    let network = crate::route_memory::current_network();
    let mut network_check = Instant::now();
    loop {
        if network_check.elapsed() >= Duration::from_secs(1) {
            network_check = Instant::now();
            if network.is_some() && crate::route_memory::current_network() != network {
                stop.store(true, Ordering::SeqCst);
            }
        }
        if stop.load(Ordering::SeqCst) || started.elapsed() > budget + Duration::from_secs(2) {
            supervisor.stop_scan_process();
            let _ = reader.join();
            return Err(if stop.load(Ordering::SeqCst) {
                "scan cancelled".into()
            } else {
                "endpoint probe timed out".into()
            });
        }
        match supervisor.poll_scan() {
            ScanState::Gone => {
                let _ = reader.join();
                return Err("scan cancelled".into());
            }
            ScanState::Exited => break,
            ScanState::Running => thread::sleep(Duration::from_millis(100)),
        }
    }
    let text = reader.join().unwrap_or_default();
    let line = text
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or("the core reported nothing")?;
    let value: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    if value["ok"] != true {
        return Err(value["error"]
            .as_str()
            .unwrap_or("endpoint probe failed")
            .into());
    }
    Ok(value)
}
fn report_process(
    core_path: &std::path::Path,
    config_dir: &std::path::Path,
    identity_path: &std::path::Path,
    profile: &CoreProfile,
    extra: &[String],
    transport: &str,
) -> Command {
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
            command.args([
                "--fragment",
                "--fragment-size",
                &profile.fragment_size,
                "--fragment-delay",
                &profile.fragment_delay,
            ]);
        }
    }
    if profile.performance_profile != "auto" {
        command.args(["--perf", &profile.performance_profile]);
    }
    crate::core_supervisor::set_engine_environment(&mut command, profile);
    crate::core_supervisor::hide_console(&mut command);

    command
}

pub enum ScanState {
    Running,
    Exited,
    Gone,
}
fn candidates_from(value: &serde_json::Value) -> Vec<ScanCandidate> {
    value["results"]
        .as_array()
        .map(|a| a.iter().filter_map(candidate_from).collect())
        .unwrap_or_default()
}
fn candidate_from(value: &serde_json::Value) -> Option<ScanCandidate> {
    Some(ScanCandidate {
        peer: value["peer"].as_str()?.into(),
        rtt_ms: value["rttMs"].as_u64()?,
        ..Default::default()
    })
}
#[cfg(test)]
mod settings_tests {
    use super::*;
    #[test]
    fn scanner_receives_the_sessions_tls_and_private_upstream_settings() {
        let p = CoreProfile {
            fragment_client_hello: true,
            ech: Some("auto".into()),
            ech_resolver: Some("tcp://1.1.1.1:53".into()),
            ech_domain: Some("keys.example".into()),
            tls_groups: Some("X25519:P-256".into()),
            tls_ciphers: Some("ECDHE-RSA-AES128-GCM-SHA256".into()),
            disable_grease: true,
            enroll_address: Some("203.0.113.10:443".into()),
            upstream_proxy: "socks5://user:secret@127.0.0.1:1080".into(),
            ..Default::default()
        };
        let command = report_process(
            std::path::Path::new("aether"),
            std::path::Path::new("config"),
            std::path::Path::new("identity.toml"),
            &p,
            &["--scan-only".into()],
            "h2",
        );
        let args: Vec<_> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for flag in [
            "--ech",
            "--ech-dns",
            "--ech-domain",
            "--tls-groups",
            "--tls-ciphers",
            "--disable-grease",
            "--api-address",
            "--fragment",
        ] {
            assert!(args.iter().any(|a| a == flag), "{flag}");
        }
        assert!(args.iter().all(|a| !a.contains("secret")));
        assert!(command
            .get_envs()
            .any(|(key, value)| key == "AETHER_UPSTREAM"
                && value.is_some_and(|v| v == p.upstream_proxy.as_str())));
        let off = CoreProfile {
            ech: Some("off".into()),
            ..p
        };
        let command = report_process(
            std::path::Path::new("aether"),
            std::path::Path::new("config"),
            std::path::Path::new("identity.toml"),
            &off,
            &[],
            "h3",
        );
        assert!(!command
            .get_args()
            .any(|a| a == "--ech-dns" || a == "--ech-domain" || a == "--fragment"));
        assert!(command
            .get_envs()
            .any(|(key, value)| key == "AETHER_ECH_DNS" && value.is_none()));
    }
}
#[cfg(test)]
mod discovery_tests {
    use super::*;
    #[test]
    fn records_only_success_survives_plain_failures_and_keeps_recipe() {
        let p = CoreProfile::default();
        let result = discover_with(
            &p,
            1,
            Duration::from_secs(210),
            vec![],
            |p, _, _| {
                if p.hello_shape == "records" {
                    Ok(vec![ScanCandidate {
                        peer: "192.0.2.1:443".into(),
                        rtt_ms: 20,
                        ..Default::default()
                    }])
                } else {
                    Err("TLS peer refused the handshake".into())
                }
            },
            || true,
        )
        .unwrap();
        assert_eq!(result.candidates[0].successful_checks, 2);
        assert_eq!(
            result.candidates[0].recipe.as_ref().unwrap().hello_shape,
            "records"
        );
        assert!(!result.diagnostics.is_empty());
    }
    #[test]
    fn failed_traffic_is_not_a_verified_result() {
        let p = CoreProfile::default();
        let result = discover_with(
            &p,
            1,
            Duration::from_secs(210),
            vec![],
            |_, action, _| {
                if action == ProbeAction::Scan {
                    Ok(vec![ScanCandidate {
                        peer: "192.0.2.1:443".into(),
                        ..Default::default()
                    }])
                } else {
                    Err("certificate validation failed".into())
                }
            },
            || true,
        )
        .unwrap();
        assert!(result.candidates.is_empty());
        assert!(result.diagnostics.iter().any(|d| d.contains("certificate")));
    }
    #[test]
    fn a_scan_that_uses_the_remaining_budget_cannot_return_unconfirmed_endpoints() {
        let result = discover_with(
            &CoreProfile::default(),
            1,
            Duration::from_millis(100),
            vec![],
            |_, action, _| {
                assert!(
                    action == ProbeAction::Scan,
                    "no time remains for traffic confirmation"
                );
                std::thread::sleep(Duration::from_millis(120));
                Ok(vec![ScanCandidate {
                    peer: "192.0.2.1:443".into(),
                    ..Default::default()
                }])
            },
            || true,
        )
        .unwrap();
        assert!(result.candidates.is_empty());
        assert!(result
            .diagnostics
            .iter()
            .any(|d| d.contains("budget expired")));
    }
    #[test]
    fn cancellation_and_registration_holds_stop_further_calls() {
        let p = CoreProfile::default();
        assert!(discover_with(
            &p,
            1,
            Duration::from_secs(10),
            vec![],
            |_, _, _| panic!("cancelled"),
            || false
        )
        .is_err());
        let mut calls = 0;
        assert!(discover_with(
            &p,
            1,
            Duration::from_secs(10),
            vec![],
            |_, _, _| {
                calls += 1;
                Err("HTTP 429 Retry-After 3600".into())
            },
            || true
        )
        .is_err());
        assert_eq!(calls, 1);
    }
}
