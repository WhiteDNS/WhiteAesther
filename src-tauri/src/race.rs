//! Android connection recovery: one sequential recipe lane per carrier.
use crate::{
    carrier::CarrierKind,
    carrier_probe::carries_verified_traffic_unless,
    core_supervisor::{engine_command, resolve_core_path, CoreProfile, CoreSupervisor},
    recovery::{self, EngineRecipe},
    route_memory::{self, Recall, Remedy, Route, RouteMemory},
    tor::{BridgeMode, TorSettings},
};
use serde::Serialize;
use std::{
    io::{BufRead, BufReader},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    process::Child,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Manager, State};
const POLL: Duration = Duration::from_millis(200);
const ENGINE_GRACE: Duration = Duration::from_secs(3);
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LaneOutcome {
    pub carrier: String,
    pub transport: Option<String>,
    pub outcome: String,
    pub detail: Option<String>,
    pub seconds: u64,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RaceReport {
    pub winner: Option<RaceWinner>,
    pub lanes: Vec<LaneOutcome>,
    pub cancelled: bool,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RaceWinner {
    pub carrier: String,
    pub masque_transport: Option<String>,
    pub protocol: Option<String>,
    pub fragment_client_hello: Option<bool>,
    pub ech: Option<String>,
    pub endpoint_mode: Option<String>,
    pub peer: Option<String>,
    pub recipe: Option<EngineRecipe>,
    pub tor: Option<TorSettings>,
    pub seconds: u64,
}

impl RaceWinner {
    pub(crate) fn apply(&self, base: &CoreProfile) -> CoreProfile {
        let mut profile = self
            .recipe
            .as_ref()
            .map(|r| r.apply(base))
            .unwrap_or_else(|| base.clone());
        profile.carriers = crate::carrier::CarrierChain {
            first: match self.carrier.as_str() {
                "psiphon" => CarrierKind::Psiphon,
                "tor" => CarrierKind::Tor,
                _ => CarrierKind::Aether,
            },
            second: None,
        };
        if let Some(mode) = &self.endpoint_mode {
            profile.endpoint_mode = mode.clone();
        }
        if let Some(peer) = &self.peer {
            profile.peer = Some(peer.clone());
        }
        if let Some(tor) = &self.tor {
            profile.tor = tor.clone();
        }
        if self.recipe.is_some() {
            profile.recovery_base = Some(
                base.recovery_base
                    .clone()
                    .unwrap_or_else(|| EngineRecipe::from_profile(base)),
            );
        }
        profile
    }
}
#[derive(Debug, Clone)]
struct Lane {
    kind: CarrierKind,
    recipe: Option<EngineRecipe>,
    tor: Option<TorSettings>,
    budget: Duration,
}
impl Lane {
    fn name(&self) -> String {
        if let Some(r) = &self.recipe {
            return r.label();
        }
        if let Some(t) = &self.tor {
            return format!(
                "tor {}",
                match t.bridges {
                    BridgeMode::Custom => "custom",
                    BridgeMode::BuiltIn => &t.transport,
                    BridgeMode::None => "direct",
                }
            );
        }
        self.kind.proxy_name().into()
    }
}
struct Group {
    kind: CarrierKind,
    routes: Vec<Lane>,
    delay: Duration,
}
fn tor_routes(p: &CoreProfile) -> Vec<Lane> {
    let mut result = Vec::new();
    if !p.tor.custom_bridges.trim().is_empty() {
        result.push(Lane {
            kind: CarrierKind::Tor,
            recipe: None,
            tor: Some(TorSettings {
                bridges: BridgeMode::Custom,
                ..p.tor.clone()
            }),
            budget: Duration::from_secs(180),
        });
    }
    for (transport, seconds) in [("snowflake", 180), ("obfs4", 150)] {
        result.push(Lane {
            kind: CarrierKind::Tor,
            recipe: None,
            tor: Some(TorSettings {
                bridges: BridgeMode::BuiltIn,
                transport: transport.into(),
                ..p.tor.clone()
            }),
            budget: Duration::from_secs(seconds),
        });
    }
    result.push(Lane {
        kind: CarrierKind::Tor,
        recipe: None,
        tor: Some(TorSettings {
            bridges: BridgeMode::None,
            ..p.tor.clone()
        }),
        budget: Duration::from_secs(90),
    });
    result
}
fn groups(p: &CoreProfile, available: &[CarrierKind], recall: &Recall) -> Vec<Group> {
    let context = recovery::context(p);
    let remembered = recall
        .engine_route
        .as_ref()
        .filter(|r| r.context.as_deref() == Some(context.as_str()))
        .and_then(|r| r.recipe.as_ref());
    let failure = recall.remedy.map(|r| match r {
        Remedy::Ech => "ECH required",
        Remedy::Fragment => "unrecognized name",
    });
    let mut result = Vec::new();
    if available.contains(&CarrierKind::Aether) {
        result.push(Group {
            kind: CarrierKind::Aether,
            delay: Duration::ZERO,
            routes: recovery::recipes(p, remembered, failure)
                .into_iter()
                .map(|r| {
                    let budget = r.budget();
                    Lane {
                        kind: CarrierKind::Aether,
                        recipe: Some(r),
                        tor: None,
                        budget,
                    }
                })
                .collect(),
        });
    }
    if available.contains(&CarrierKind::Psiphon) {
        result.push(Group {
            kind: CarrierKind::Psiphon,
            delay: Duration::from_secs(if remembered.is_some() { 30 } else { 0 }),
            routes: vec![Lane {
                kind: CarrierKind::Psiphon,
                recipe: None,
                tor: None,
                budget: Duration::from_secs(330),
            }],
        });
    }
    if available.contains(&CarrierKind::Tor) {
        result.push(Group {
            kind: CarrierKind::Tor,
            delay: Duration::from_secs(if remembered.is_some() { 45 } else { 15 }),
            routes: tor_routes(p),
        });
    }
    result
}
fn trial_profile(p: &CoreProfile, lane: &Lane) -> CoreProfile {
    let mut p = lane
        .recipe
        .as_ref()
        .map(|r| r.apply(p))
        .unwrap_or_else(|| p.clone());
    p.endpoint_mode = "automatic".into();
    p.peer = None;
    p.h2_peer = None;
    p.wg_peer = None;
    p.auto_reconnect = false;
    p
}
fn route_of(p: &CoreProfile, lane: &Lane) -> Route {
    let trial = trial_profile(p, lane);
    Route {
        carrier: lane.kind.proxy_name().into(),
        protocol: lane.recipe.as_ref().map(|r| r.protocol.clone()),
        transport: lane.recipe.as_ref().map(|r| r.masque_transport.clone()),
        fragment: trial.fragment_client_hello && trial.masque_transport == "h2",
        ech: trial.ech_setting().map(str::to_string),
        recipe: lane.recipe.clone(),
        context: Some(recovery::context(p)),
        tor: lane.tor.clone(),
    }
}
fn free_port() -> Result<u16, String> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|s| s.local_addr())
        .map(|s| s.port())
        .map_err(|e| e.to_string())
}
struct TrialEngine(Child);
impl Drop for TrialEngine {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn run_lane(
    app: &AppHandle,
    lane: &Lane,
    p: &CoreProfile,
    stop: &AtomicBool,
    remedy: &Mutex<Option<Remedy>>,
) -> Result<Option<String>, String> {
    if stop.load(Ordering::SeqCst) {
        return Err("search cancelled".into());
    }
    let deadline = Instant::now() + lane.budget;
    let endpoint = Arc::new(Mutex::new(None));
    let error = Arc::new(Mutex::new(None::<String>));
    let (listener, mut engine) = match lane.kind {
        CarrierKind::Aether => {
            let mut trial = trial_profile(p, lane);
            trial.socks_address = format!("127.0.0.1:{}", free_port()?);
            let path = resolve_core_path(app, p.core_path.as_deref())?;
            let mut child = engine_command(app, &trial, &path)?
                .spawn()
                .map_err(|e| format!("cannot start trial: {e}"))?;
            if let Some(stdout) = child.stdout.take() {
                thread::spawn(move || {
                    let _ = std::io::copy(&mut BufReader::new(stdout), &mut std::io::sink());
                });
            }
            if let Some(stderr) = child.stderr.take() {
                let endpoint = endpoint.clone();
                let error = error.clone();
                thread::spawn(move || {
                    for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                        if let Some(peer) = crate::core_supervisor::parse_endpoint(&line) {
                            if let Ok(mut slot) = endpoint.lock() {
                                *slot = Some(peer);
                            }
                        }
                        if let Ok(mut slot) = error.lock() {
                            *slot = Some(line);
                        }
                    }
                });
            }
            (
                trial
                    .socks_address
                    .parse::<SocketAddr>()
                    .map_err(|e| e.to_string())?,
                Some(TrialEngine(child)),
            )
        }
        CarrierKind::Psiphon => {
            let mut settings = p.psiphon.clone();
            settings.egress_region.clear();
            (
                app.state::<crate::psiphon::Psiphon>().start_for_search(
                    app,
                    &settings,
                    lane.budget,
                )?,
                None,
            )
        }
        CarrierKind::Tor => (
            app.state::<crate::tor::Tor>().start_for_search(
                app,
                lane.tor.as_ref().unwrap_or(&p.tor),
                lane.budget,
            )?,
            None,
        ),
    };
    let mut last = "route did not carry verified traffic".to_string();
    while Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
        if let Ok(slot) = error.lock() {
            if let Some(line) = slot.as_deref() {
                if let Some(named) = Remedy::named_in(line) {
                    if let Ok(mut slot) = remedy.lock() {
                        *slot = Some(named);
                    }
                }
            }
        }
        if let Some(child) = engine.as_mut() {
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                return Err(error
                    .lock()
                    .ok()
                    .and_then(|e| e.clone())
                    .unwrap_or_else(|| format!("trial engine exited: {status}")));
            }
        }
        match carries_verified_traffic_unless(listener, &|| {
            stop.load(Ordering::SeqCst) || Instant::now() >= deadline
        }) {
            Ok(()) => return Ok(endpoint.lock().ok().and_then(|p| p.clone())),
            Err(reason) => last = reason,
        }
        thread::sleep(POLL);
    }
    Err(if stop.load(Ordering::SeqCst) {
        "search cancelled".into()
    } else {
        last
    })
}
enum Event {
    Attempt(Lane, Result<Option<String>, String>, u64),
    Done(CarrierKind),
}
fn wait_unless(stop: &AtomicBool, until: Instant) {
    while Instant::now() < until && !stop.load(Ordering::SeqCst) {
        thread::sleep(POLL);
    }
}
fn run_group(
    app: AppHandle,
    group: Group,
    profile: CoreProfile,
    stop: Arc<AtomicBool>,
    sender: mpsc::Sender<Event>,
    ceiling: Duration,
    remedy: Arc<Mutex<Option<Remedy>>>,
) {
    let began = Instant::now();
    wait_unless(&stop, began + group.delay);
    let deadline = began + ceiling;
    let mut round = 0;
    while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
        let round_started = Instant::now();
        for lane in &group.routes {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            if round > 0 && deadline.saturating_duration_since(Instant::now()) < lane.budget {
                break;
            }
            let mut lane = lane.clone();
            if lane.kind == CarrierKind::Psiphon {
                lane.budget = lane
                    .budget
                    .max(deadline.saturating_duration_since(Instant::now()));
            }
            let started = Instant::now();
            let result = run_lane(&app, &lane, &profile, &stop, &remedy);
            let carried = result.is_ok();
            let conclusive = result
                .as_ref()
                .err()
                .is_some_and(|e| recovery::conclusive_identity_error(e));
            let _ = sender.send(Event::Attempt(
                lane.clone(),
                result,
                started.elapsed().as_secs(),
            ));
            if carried || (conclusive && lane.kind == CarrierKind::Aether) {
                let _ = sender.send(Event::Done(group.kind));
                return;
            }
            if lane.kind == CarrierKind::Tor {
                app.state::<crate::tor::Tor>().stop();
            }
        }
        round += 1;
        let pause = recovery::pause_after_round(round_started.elapsed(), round);
        if Instant::now() + pause >= deadline {
            break;
        }
        wait_unless(&stop, Instant::now() + pause);
    }
    let _ = sender.send(Event::Done(group.kind));
}
fn winner(p: &CoreProfile, lane: &Lane, peer: Option<String>, seconds: u64) -> RaceWinner {
    let recipe = lane.recipe.clone();
    RaceWinner {
        carrier: lane.kind.proxy_name().into(),
        masque_transport: recipe.as_ref().map(|r| r.masque_transport.clone()),
        protocol: recipe.as_ref().map(|r| r.protocol.clone()),
        fragment_client_hello: recipe.as_ref().map(|r| r.fragment_client_hello),
        ech: recipe.as_ref().and_then(|r| r.ech.clone()),
        endpoint_mode: recipe.as_ref().map(|_| {
            if peer.is_some() || p.endpoint_mode == "custom-only" {
                "custom-first".into()
            } else {
                p.endpoint_mode.clone()
            }
        }),
        peer,
        recipe,
        tor: lane.tor.clone(),
        seconds,
    }
}
#[tauri::command]
pub async fn race_carriers(
    app: AppHandle,
    supervisor: State<'_, CoreSupervisor>,
    profile: CoreProfile,
) -> Result<RaceReport, String> {
    let supervisor = supervisor.inner().clone();
    tauri::async_runtime::spawn_blocking(move || search_blocking(app, supervisor, profile))
        .await
        .map_err(|e| format!("connection search failed: {e}"))?
}

pub(crate) fn search_blocking(
    app: AppHandle,
    supervisor: CoreSupervisor,
    profile: CoreProfile,
) -> Result<RaceReport, String> {
    let profile = profile
        .recovery_base
        .as_ref()
        .map(|r| r.apply(&profile))
        .unwrap_or(profile);
    profile.validate()?;
    let stop = supervisor.begin_search()?;
    let generation = supervisor.current_generation();
    let memory_path = app
        .path()
        .app_config_dir()
        .ok()
        .map(|p| p.join("route-memory.json"));
    let network = route_memory::current_network();
    let recall = match (&network, &memory_path) {
        (Some(n), Some(p)) => RouteMemory::load(p).recall(n, route_memory::now_unix()),
        _ => Recall::default(),
    };
    let available = crate::carriers_installed(&app);
    let groups = groups(&profile, &available, &recall);
    let supervisor = supervisor.clone();
    let started = Instant::now();
    let ceiling = groups
        .iter()
        .map(|g| g.delay + g.routes.iter().map(|l| l.budget).sum::<Duration>())
        .max()
        .unwrap_or(Duration::ZERO);
    let expected = groups.len();
    supervisor.show_search(true, Some("Searching for a working connection".into()));
    let (sender, receiver) = mpsc::channel();
    let remedy = Arc::new(Mutex::new(None));
    let mut workers = Vec::new();
    for group in groups {
        let (app, stop, sender, profile, remedy) = (
            app.clone(),
            stop.clone(),
            sender.clone(),
            profile.clone(),
            remedy.clone(),
        );
        workers.push(thread::spawn(move || {
            run_group(app, group, profile, stop, sender, ceiling, remedy)
        }));
    }
    drop(sender);
    let (mut done, mut engine_done) = (0, !available.contains(&CarrierKind::Aether));
    let mut chosen: Option<(Lane, Option<String>)> = None;
    let mut provisional: Option<(Lane, Option<String>, Instant)> = None;
    let mut outcomes = Vec::new();
    let mut cancelled = false;
    let mut network_check = Instant::now();
    loop {
        if stop.load(Ordering::SeqCst) {
            cancelled = true;
            break;
        }
        if network_check.elapsed() >= Duration::from_secs(1) {
            network_check = Instant::now();
            if network.is_some() && route_memory::current_network() != network {
                cancelled = true;
                break;
            }
        }
        if provisional
            .as_ref()
            .is_some_and(|(_, _, at)| at.elapsed() >= ENGINE_GRACE || engine_done)
        {
            let (lane, peer, _) = provisional.take().unwrap();
            chosen = Some((lane, peer));
            break;
        }
        if done >= expected {
            break;
        }
        match receiver.recv_timeout(POLL) {
            Ok(Event::Done(kind)) => {
                done += 1;
                if kind == CarrierKind::Aether {
                    engine_done = true;
                }
            }
            Ok(Event::Attempt(lane, result, seconds)) => {
                let carried = result.is_ok();
                let peer = result.as_ref().ok().cloned().flatten();
                supervisor.log(
                    if carried { "info" } else { "warn" },
                    format!(
                        "searching: {}: {} ({seconds}s)",
                        lane.name(),
                        result
                            .as_ref()
                            .err()
                            .map(String::as_str)
                            .unwrap_or("verified traffic")
                    ),
                );
                outcomes.push(LaneOutcome {
                    carrier: lane.kind.proxy_name().into(),
                    transport: Some(lane.name()),
                    outcome: if carried {
                        "carried".into()
                    } else {
                        "failed".into()
                    },
                    detail: result.err(),
                    seconds,
                });
                if carried {
                    if lane.kind == CarrierKind::Aether || engine_done {
                        chosen = Some((lane, peer));
                        break;
                    }
                    if provisional.is_none() {
                        provisional = Some((lane, peer, Instant::now()));
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if chosen.is_none() && !cancelled {
        chosen = provisional.map(|(l, p, _)| (l, p));
    }
    stop.store(true, Ordering::SeqCst);
    app.state::<crate::psiphon::Psiphon>().stop();
    app.state::<crate::tor::Tor>().stop();
    // Join old workers before the winning carrier belongs to a new session.
    for worker in workers {
        let _ = worker.join();
    }
    if supervisor.current_generation() != generation
        || (network.is_some() && route_memory::current_network() != network)
    {
        cancelled = true;
        chosen = None;
    }
    for event in receiver.try_iter() {
        if let Event::Attempt(lane, result, seconds) = event {
            outcomes.push(LaneOutcome {
                carrier: lane.kind.proxy_name().into(),
                transport: Some(lane.name()),
                outcome: if result.is_ok() {
                    "carried".into()
                } else {
                    "failed".into()
                },
                detail: result.err(),
                seconds,
            });
        }
    }
    let result = if cancelled {
        None
    } else {
        chosen
            .as_ref()
            .map(|(l, p)| winner(&profile, l, p.clone(), started.elapsed().as_secs()))
    };
    if !cancelled {
        if let (Some(path), Some(network)) = (&memory_path, &network) {
            let mut memory = RouteMemory::load(path);
            let now = route_memory::now_unix();
            if let Some((lane, _)) = &chosen {
                memory.record_win(network, route_of(&profile, lane), now);
            }
            if !chosen
                .as_ref()
                .is_some_and(|(l, _)| l.kind == CarrierKind::Aether)
            {
                memory.record_engine_failure(
                    network,
                    engine_done,
                    remedy.lock().ok().and_then(|r| *r),
                    now,
                );
            }
            if let Err(e) = memory.save(path) {
                supervisor.log("warn", format!("cannot remember route: {e}"));
            }
        }
    }
    supervisor.finish_search(&stop);
    Ok(RaceReport {
        winner: result,
        lanes: outcomes,
        cancelled,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_engine_lane_covers_every_recipe() {
        let g = groups(
            &CoreProfile::default(),
            &[CarrierKind::Aether, CarrierKind::Psiphon, CarrierKind::Tor],
            &Recall::default(),
        );
        assert_eq!(g.len(), 3);
        assert!(g[0].routes.iter().any(|l| l.name() == "aether h2+records"));
        assert!(g[0].routes.iter().any(|l| l.name() == "aether h3+ech"));
        assert_eq!(g[2].delay, Duration::from_secs(15));
    }
    #[test]
    fn tor_tries_custom_snowflake_obfs4_direct() {
        let mut p = CoreProfile::default();
        p.tor.custom_bridges = "obfs4 192.0.2.1:443 key".into();
        assert_eq!(
            tor_routes(&p).iter().map(Lane::name).collect::<Vec<_>>(),
            vec!["tor custom", "tor snowflake", "tor obfs4", "tor direct"]
        );
    }
    #[test]
    fn unavailable_carriers_have_no_worker() {
        assert!(groups(&CoreProfile::default(), &[], &Recall::default()).is_empty());
        assert_eq!(
            groups(
                &CoreProfile::default(),
                &[CarrierKind::Psiphon],
                &Recall::default()
            )
            .len(),
            1
        );
    }
    #[test]
    fn successful_recipe_is_preserved_and_gets_the_next_lead() {
        let p = CoreProfile::default();
        let recipe = recovery::recipes(&p, None, None)
            .into_iter()
            .find(|r| r.label() == "aether h2+compact")
            .unwrap();
        let lane = Lane {
            kind: CarrierKind::Aether,
            budget: recipe.budget(),
            recipe: Some(recipe.clone()),
            tor: None,
        };
        let recall = Recall {
            engine_route: Some(route_of(&p, &lane)),
            remedy: None,
        };
        let g = groups(&p, &[CarrierKind::Aether, CarrierKind::Psiphon], &recall);
        assert_eq!(g[0].routes[0].recipe, Some(recipe.clone()));
        assert_eq!(g[1].delay, Duration::from_secs(30));
        let w = winner(&p, &lane, Some("192.0.2.1:443".into()), 1);
        assert_eq!(w.recipe, Some(recipe));
        assert_eq!(w.peer.as_deref(), Some("192.0.2.1:443"));
    }
    #[test]
    fn changed_tls_invalidates_the_recipe() {
        let p = CoreProfile::default();
        let lane = groups(&p, &[CarrierKind::Aether], &Recall::default())
            .remove(0)
            .routes
            .remove(2);
        let recall = Recall {
            engine_route: Some(route_of(&p, &lane)),
            remedy: None,
        };
        let mut changed = p.clone();
        changed.tls.masque_sni = Some("example.com".into());
        assert_eq!(
            groups(&changed, &[CarrierKind::Aether], &recall)[0].routes[0].name(),
            "aether h2"
        );
    }
    #[test]
    fn trials_clear_pins_without_losing_upstream_or_tls() {
        let mut p = CoreProfile::default();
        p.peer = Some("192.0.2.1:443".into());
        p.h2_peer = p.peer.clone();
        p.endpoint_mode = "custom-only".into();
        p.upstream_proxy = "socks5://user:secret@127.0.0.1:1234".into();
        p.tls.tls13_ciphers = Some("TLS_AES_128_GCM_SHA256".into());
        let lane = groups(&p, &[CarrierKind::Aether], &Recall::default())
            .remove(0)
            .routes
            .remove(0);
        let trial = trial_profile(&p, &lane);
        assert!(trial.peer.is_none() && trial.h2_peer.is_none());
        assert!(!trial.auto_reconnect);
        assert_eq!(trial.upstream_proxy, p.upstream_proxy);
        assert_eq!(trial.tls, p.tls);
    }
}
