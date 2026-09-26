//! Start every way out at once, and keep the first that proves itself.
//!
//! The search this sits in front of tries nine orderings in turn. That is the
//! right shape for the rare case where nothing single works and pairs have to
//! be tried, and the wrong shape for the ordinary one: a network where the
//! engine cannot get out but Psiphon can made someone wait out the engine's
//! whole budget -- minutes -- before Psiphon was even started. Started
//! together, Psiphon answers in its own time and the wait is the *fastest*
//! carrier rather than the sum of the ones that failed first.
//!
//! ## Why the single carriers and not the pairs
//!
//! Three carriers exist and every pair uses two of them, so no two pairs can
//! run at once -- there is no fourth carrier to give the second pair. Pairs
//! stay sequential in the frontend sweep, which is where they belong: they are
//! the fallback for when all of this has already failed.
//!
//! ## One route at a time per carrier
//!
//! `Psiphon` and `Tor` are one managed instance each, and `start` on either
//! begins by stopping whatever it was doing. That is not an obstacle to racing,
//! it is the shape of it: the lanes are *carriers*, not routes, so nothing ever
//! asks for two Psiphons. The engine is the exception -- a trial engine is an
//! ordinary child process on a private port, so both MASQUE framings can run at
//! once, which is the whole point of racing them.
//!
//! ## The race owns everything it starts
//!
//! Including the winner. The trial carriers are all stopped before this
//! returns, and the identity of the winner goes back for the ordinary connect
//! path to start cleanly. That costs the winner one more connect, and buys
//! something worth more: the code that decides where a person's traffic
//! actually goes is not touched by any of this. A trial is a question, not a
//! session -- it claims no snapshot, applies no system proxy and starts no
//! routing engine.

use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::carrier::CarrierKind;
use crate::carrier_probe::carries_verified_traffic_unless;
use crate::core_supervisor::{engine_command, resolve_core_path, CoreProfile, CoreSupervisor};
use crate::route_memory::{self, Recall, Remedy, Route, RouteMemory};

/// How long any one lane may take before it is abandoned.
///
/// Each carrier's own deadline, as the sequential sweep uses: the engine scans
/// to the prober's deadline and then hands over, Psiphon may need tunnel-core's
/// full establish window on a first run, and Tor builds three hops. A lane cut
/// below these is a lane that answers "no" for a carrier that was still working.
fn lane_budget(kind: CarrierKind, profile: &CoreProfile) -> Duration {
    match kind {
        CarrierKind::Aether => crate::core_supervisor::aether_hop_timeout(profile),
        CarrierKind::Psiphon => Duration::from_secs(330),
        CarrierKind::Tor => Duration::from_secs(195),
    }
}

/// How often a lane asks whether what it started is carrying traffic yet.
const POLL: Duration = Duration::from_secs(1);

/// How long to wait for a losing lane to say what it did.
///
/// Waited on a thread of its own, after the answer has already gone back, so
/// this costs nobody anything. Sized against one probe rather than against
/// patience: a lane inside a probe only notices the stop flag when that probe
/// returns, so anything shorter than a target's own timeout loses the evidence
/// -- which is what three seconds did on the first attempt at this.
const STRAGGLER_GRACE: Duration = Duration::from_secs(40);

/// What every lane did, so a search that found nothing can still be checked.
///
/// A race that ends with "nothing got out" and no record of what each way out
/// actually did is a race nobody can audit -- and on a network with severe
/// disruption the failure that matters is a *working* route being discarded,
/// which leaves no trace at all unless the attempt writes one.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LaneOutcome {
    pub carrier: String,
    pub transport: Option<String>,
    /// "carried", "failed", or "running" for a lane still going when the race
    /// ended -- which is not the same as one that was ruled out.
    pub outcome: String,
    pub detail: Option<String>,
    pub seconds: u64,
}

/// What the race settled on, and what everything else did.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RaceReport {
    pub winner: Option<RaceWinner>,
    pub lanes: Vec<LaneOutcome>,
}

/// What the race settled on.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RaceWinner {
    /// The carrier that proved itself, as the profile names it.
    pub carrier: String,
    /// Which MASQUE framing won, when the winner was the engine on one. The
    /// profile has to carry this into the connect that follows, or the race
    /// proves one thing and the session runs another.
    pub masque_transport: Option<String>,
    /// The protocol the winning lane ran, when it is not the one the profile
    /// already holds. `mim` is its own protocol rather than a MASQUE framing,
    /// so a winner on it changes this instead of the field above.
    pub protocol: Option<String>,
    /// Whether the winning engine lane split its ClientHello. Carried for the
    /// same reason as the framing: a lane that got out *because* of its tactic
    /// proves nothing about a session that runs without it.
    pub fragment_client_hello: Option<bool>,
    /// The ECH setting the winning engine lane ran with.
    pub ech: Option<String>,
    /// The endpoint mode the session should run with, when it is not the
    /// profile's own: a pin the user set without a fallback still gets one
    /// here, because the race found this way out without that address.
    pub endpoint_mode: Option<String>,
    /// How long it took to answer, for the line that says so on screen.
    pub seconds: u64,
}

/// One thing the race will try.
#[derive(Debug, Clone)]
struct Lane {
    kind: CarrierKind,
    /// Only meaningful for the engine.
    transport: Option<&'static str>,
    /// Split the ClientHello on this lane, whatever the profile says: the
    /// route that last got out here did, or the last failure here asked for
    /// it. Only ever switches a tactic on.
    fragment: bool,
    /// Run this lane with this ECH setting, for the same two reasons.
    ech: Option<String>,
}

impl Lane {
    fn plain(kind: CarrierKind, transport: Option<&'static str>) -> Self {
        Self { kind, transport, fragment: false, ech: None }
    }

    /// How this lane is named in the log, framing and tactic included.
    fn name(&self) -> String {
        let mut name = match self.transport {
            Some(transport) => format!("{} {transport}", self.kind.proxy_name()),
            None => self.kind.proxy_name().to_string(),
        };
        if self.fragment {
            name.push_str("+fragment");
        }
        if let Some(ech) = &self.ech {
            name.push_str(&format!("+ech {ech}"));
        }
        name
    }
}

/// The lanes to run, given what is installed and what the profile asks for.
///
/// Both MASQUE framings when the profile is on MASQUE, because H2 and H3 are
/// not interchangeable per network -- one user's Wi-Fi reached Cloudflare over
/// QUIC only, while the known mobile case is the opposite -- and the retry
/// machinery already alternates them for exactly that reason.
///
/// A profile fixed to WireGuard, WARP-in-WARP or nested MASQUE gets its own
/// lane *and* both MASQUE framings behind it. Racing only the lane it chose
/// meant a search that could not search: on a network that blocks WireGuard,
/// the engine had one way to try and it was the one that was blocked. Here the
/// framings run alongside, so this costs processes rather than time. The
/// screens still show the protocol the user chose, and a carrier picked by hand
/// still runs exactly that; only the search reads it more widely.
fn lanes(profile: &CoreProfile, available: &[CarrierKind]) -> Vec<Lane> {
    let mut lanes = Vec::new();
    if available.contains(&CarrierKind::Aether) {
        if profile.protocol == "masque" {
            lanes.push(Lane::plain(CarrierKind::Aether, Some("h2")));
            lanes.push(Lane::plain(CarrierKind::Aether, Some("h3")));
            // Two nested MASQUE hops, raced last among the engine's lanes
            // because it is the slowest and the most work. It exists for the
            // network that has learnt to recognise a single MASQUE hop, and on
            // that network it is the only engine lane that can get out -- so it
            // has to be tried without anybody knowing to ask for it. Nobody
            // opens Advanced.
            lanes.push(Lane::plain(CarrierKind::Aether, Some("mim")));
        } else {
            lanes.push(Lane::plain(CarrierKind::Aether, None));
            lanes.push(Lane::plain(CarrierKind::Aether, Some("h2")));
            lanes.push(Lane::plain(CarrierKind::Aether, Some("h3")));
        }
    }
    for kind in [CarrierKind::Psiphon, CarrierKind::Tor] {
        if available.contains(&kind) {
            lanes.push(Lane::plain(kind, None));
        }
    }
    lanes
}

/// Carries what this network remembers into the lanes, and says whether a
/// remembered engine route was given the lead.
///
/// The race runs every lane at once, so "the remembered route goes first"
/// means its lane runs with the tactic that got it out, instead of plain. And
/// the remedy the engine's last failure here named goes to the lane that can
/// act on it: ECH demanded, so H3 runs with ECH required; the server name
/// refused, so H2 splits its ClientHello. Nothing else is read from failure
/// text.
fn apply_recall(lanes: &mut [Lane], profile: &CoreProfile, recall: &Recall) -> bool {
    let mut had_lead = false;
    if let Some(route) = &recall.engine_route {
        let wanted = match route.protocol.as_deref() {
            Some("masque") => route.transport.as_deref(),
            Some("mim") if profile.protocol != "mim" => Some("mim"),
            Some(protocol) if protocol == profile.protocol => None,
            // A protocol this profile no longer runs has no lane to lead.
            _ => Some("-"),
        };
        if let Some(lane) = lanes
            .iter_mut()
            .find(|lane| lane.kind == CarrierKind::Aether && lane.transport == wanted)
        {
            lane.fragment |= route.fragment;
            if route.ech.is_some() {
                lane.ech = route.ech.clone();
            }
            had_lead = true;
        }
    }
    let (framing, remedy) = match recall.remedy {
        Some(Remedy::Ech) => (Some("h3"), Remedy::Ech),
        Some(Remedy::Fragment) => (Some("h2"), Remedy::Fragment),
        None => return had_lead,
    };
    if let Some(lane) = lanes
        .iter_mut()
        .find(|lane| lane.kind == CarrierKind::Aether && lane.transport == framing)
    {
        match remedy {
            Remedy::Ech => {
                if lane.ech.is_none() {
                    lane.ech = Some("require".into());
                }
            }
            Remedy::Fragment => lane.fragment = true,
        }
    }
    had_lead
}

/// The profile one engine lane runs, derived from the user's.
///
/// Automatic searches on its own terms here. Three settings that are right for
/// a session are wrong for a search:
/// - A scan depth past `balanced` fits no race: `thorough` alone holds a lane
///   open for five minutes and more, and the race is only as quick as the lane
///   it waits on. Capped here, not in the profile.
/// - An endpoint pinned without a fallback made every engine lane dial one
///   address on every network. The engine's command line has no "pin, then
///   fall back", so the trials search, and the session that follows a win gets
///   the pin first and then the search -- see [`session_endpoint_mode`].
/// - A trial retries nothing: the race's own deadline is its only budget.
fn trial_profile(profile: &CoreProfile, lane: &Lane) -> CoreProfile {
    let mut trial = profile.clone();
    match lane.transport {
        // Its own protocol rather than a MASQUE framing, so it sets
        // `protocol` and leaves `masque_transport` alone.
        Some("mim") => trial.protocol = "mim".into(),
        Some(transport) => {
            trial.protocol = "masque".into();
            trial.masque_transport = transport.into();
        }
        None => {}
    }
    if lane.fragment {
        trial.fragment_client_hello = true;
    }
    if let Some(ech) = &lane.ech {
        trial.ech = Some(ech.clone());
    }
    if matches!(trial.scan_mode.as_str(), "thorough" | "stealth" | "ironclad") {
        trial.scan_mode = "balanced".into();
    }
    trial.endpoint_mode = "automatic".into();
    trial.auto_reconnect = false;
    trial
}

/// The endpoint mode a session started from a race should run with, when it
/// differs from the profile's: a pin without a fallback gets one.
fn session_endpoint_mode(profile: &CoreProfile) -> Option<String> {
    (profile.endpoint_mode == "custom-only").then(|| "custom-first".into())
}

/// What a lane ran, as a route worth remembering.
///
/// Read from the arguments the trial was given, not from the lane's name --
/// the same conditions `CoreProfile::args` puts on each flag -- so a tactic the
/// user turned on by hand is remembered as part of what worked, and a setting
/// the framing ignores is not.
fn route_of(kind: CarrierKind, trial: &CoreProfile) -> Route {
    if kind != CarrierKind::Aether {
        return Route {
            carrier: kind.proxy_name().into(),
            protocol: None,
            transport: None,
            fragment: false,
            ech: None,
        };
    }
    let masque = trial.protocol == "masque";
    let h2 = masque && trial.masque_transport == "h2";
    Route {
        carrier: kind.proxy_name().into(),
        protocol: Some(trial.protocol.clone()),
        transport: masque.then(|| trial.masque_transport.clone()),
        fragment: h2 && trial.fragment_client_hello,
        // HTTP/2 does not carry ECH, so on H2 the setting did nothing.
        ech: trial
            .ech
            .clone()
            .filter(|ech| !ech.trim().is_empty() && ech != "off")
            .filter(|_| masque && !h2),
    }
}

/// A local port nothing is listening on.
///
/// Bound and released rather than guessed: two engine lanes start within
/// milliseconds of each other, and a guessed pair of ports collides often
/// enough to look like one framing simply never working.
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

/// A trial engine, which kills its process when it goes out of scope.
///
/// A losing lane is abandoned the moment another one wins, and an engine inside
/// a gateway scan does not stop being inside it because nobody is waiting any
/// more. Nothing here is allowed to outlive the race.
struct TrialEngine(Option<Child>);

impl Drop for TrialEngine {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Runs one lane to its own deadline, and says whether it carried traffic.
fn run_lane(
    app: &AppHandle,
    lane: &Lane,
    profile: &CoreProfile,
    stop: &AtomicBool,
    remedy: &Arc<Mutex<Option<Remedy>>>,
) -> Result<SocketAddr, String> {
    let trial = trial_profile(profile, lane);
    let deadline = Instant::now() + lane_budget(lane.kind, &trial);

    // Whatever this lane started, so it can be asked whether it is carrying
    // yet. The engine keeps its child alive in `_engine` for the whole lane.
    let (listener, _engine) = match lane.kind {
        CarrierKind::Aether => {
            let mut trial = trial;
            // Its own listener, so two engine lanes and whatever the user
            // already has running never contend for one port.
            let port = free_port()?;
            trial.socks_address = format!("127.0.0.1:{port}");

            let core_path = resolve_core_path(app, profile.core_path.as_deref())?;
            let mut command = engine_command(app, &trial, &core_path)?;
            let mut child = command
                .spawn()
                .map_err(|error| format!("failed to start a trial engine: {error}"))?;
            // Both streams are piped, so both are read: a pipe nobody reads
            // fills, and an engine blocked writing its log stops scanning.
            // The log is also where a failure that names its own remedy
            // shows up, which the next race on this network acts on.
            if let Some(stdout) = child.stdout.take() {
                thread::spawn(move || {
                    let _ = std::io::copy(&mut BufReader::new(stdout), &mut std::io::sink());
                });
            }
            if let Some(stderr) = child.stderr.take() {
                let remedy = remedy.clone();
                thread::spawn(move || watch_for_remedy(stderr, &remedy));
            }
            let address: SocketAddr = trial
                .socks_address
                .parse()
                .map_err(|_| format!("{} is not an address", trial.socks_address))?;
            (address, Some(TrialEngine(Some(child))))
        }
        CarrierKind::Psiphon => {
            let psiphon = app.state::<crate::psiphon::Psiphon>();
            (psiphon.start(app, &profile.psiphon, None)?, None)
        }
        CarrierKind::Tor => {
            let tor = app.state::<crate::tor::Tor>();
            (tor.start(app, &profile.tor, None)?, None)
        }
    };

    // And now the only question that matters. Asked on a loop rather than once:
    // a listener exists well before the route behind it settles, and a probe in
    // that first moment says nothing.
    let mut last = String::from("never answered");
    while Instant::now() < deadline {
        if stop.load(Ordering::SeqCst) {
            return Err("another way out answered first".into());
        }
        match carries_verified_traffic_unless(listener, &|| stop.load(Ordering::SeqCst)) {
            Ok(()) => return Ok(listener),
            Err(reason) => last = reason,
        }
        thread::sleep(POLL);
    }
    Err(last)
}

/// Where the route memory lives, beside the profile.
fn route_memory_path(app: &AppHandle) -> Option<std::path::PathBuf> {
    app.path()
        .app_config_dir()
        .ok()
        .map(|dir| dir.join("route-memory.json"))
}

/// How many engine lanes a race on this profile starts.
fn expected_engine_lanes(profile: &CoreProfile, available: &[CarrierKind]) -> usize {
    lanes(profile, available)
        .iter()
        .filter(|lane| lane.kind == CarrierKind::Aether)
        .count()
}

/// Reads an engine's log to its end, keeping the last remedy a failure named.
fn watch_for_remedy(stream: impl Read, remedy: &Mutex<Option<Remedy>>) {
    for line in BufReader::new(stream).lines() {
        let Ok(line) = line else { break };
        if let Some(named) = Remedy::named_in(&line) {
            if let Ok(mut slot) = remedy.lock() {
                *slot = Some(named);
            }
        }
    }
}

/// Starts every way out at once and returns the first that carries traffic.
///
/// `Ok(None)` means every lane finished and none of them did -- which is the
/// point at which the sweep's chained orderings are worth trying.
#[tauri::command]
pub async fn race_carriers(
    app: AppHandle,
    supervisor: State<'_, CoreSupervisor>,
    profile: CoreProfile,
) -> Result<RaceReport, String> {
    profile.validate()?;
    // A race brings carriers up and takes them down again; doing that under a
    // live session would stop the connection the person is using.
    if supervisor.connected_socks().is_some() {
        return Err("disconnect before searching for a way out".into());
    }

    let available = crate::carriers_installed(&app);
    let mut lanes = lanes(&profile, &available);
    if lanes.is_empty() {
        return Ok(RaceReport { winner: None, lanes: Vec::new() });
    }

    // What got out last time on this network, carried into the lanes. Read
    // before anything starts: a trial engine opens no adapter, but nothing
    // here should depend on that staying true.
    let memory_path = route_memory_path(&app);
    let network = route_memory::current_network();
    let recall = match (&network, &memory_path) {
        (Some(network), Some(path)) => {
            RouteMemory::load(path).recall(network, route_memory::now_unix())
        }
        _ => Recall::default(),
    };
    let had_lead = apply_recall(&mut lanes, &profile, &recall);

    let supervisor = supervisor.inner().clone();
    let app_for_race = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let started = Instant::now();
        let stop = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel::<(Lane, Result<SocketAddr, String>, u64)>();
        let expected = lanes.len();
        if had_lead {
            supervisor.log(
                "info",
                "searching: this network got out on the engine last time; its lane runs the \
                 same way"
                    .into(),
            );
        }

        supervisor.show_search(true, Some(format!("Trying {expected} ways out at once")));
        supervisor.log(
            "info",
            format!(
                "searching: {} started together",
                lanes.iter().map(Lane::name).collect::<Vec<_>>().join(", ")
            ),
        );

        // One per lane: the last failure each engine named as fixable.
        let mut remedies: Vec<Arc<Mutex<Option<Remedy>>>> = Vec::with_capacity(expected);
        for lane in lanes {
            let app = app_for_race.clone();
            let profile = profile.clone();
            let stop = stop.clone();
            let sender = sender.clone();
            let remedy = Arc::new(Mutex::new(None));
            remedies.push(remedy.clone());
            thread::spawn(move || {
                let began = Instant::now();
                let outcome = run_lane(&app, &lane, &profile, &stop, &remedy);
                // A lane that finishes after the race is over has nobody to
                // tell, and that is fine -- the receiver is gone and the send
                // fails harmlessly.
                let _ = sender.send((lane, outcome, began.elapsed().as_secs()));
            });
        }
        // The loop below ends when every clone is gone, so this one must not
        // outlive the sends.
        drop(sender);

        let mut winner = None;
        let mut winner_route: Option<Route> = None;
        let mut outcomes: Vec<LaneOutcome> = Vec::with_capacity(expected);
        while outcomes.len() < expected {
            let Ok((lane, result, seconds)) = receiver.recv() else {
                break;
            };
            let carried = result.is_ok();
            supervisor.log(
                if carried { "info" } else { "warn" },
                match &result {
                    Ok(_) => format!("searching: {} carried traffic after {seconds}s", lane.name()),
                    Err(reason) => format!(
                        "searching: {} did not carry after {seconds}s -- {reason}",
                        lane.name()
                    ),
                },
            );
            outcomes.push(LaneOutcome {
                carrier: lane.kind.proxy_name().into(),
                transport: lane.transport.map(str::to_string),
                outcome: if carried { "carried".into() } else { "failed".into() },
                detail: result.err(),
                seconds,
            });
            if carried {
                // What the lane actually ran, which is what the session has to
                // run and what this network should remember.
                let trial = trial_profile(&profile, &lane);
                let engine = lane.kind == CarrierKind::Aether;
                winner_route = Some(route_of(lane.kind, &trial));
                winner = Some(RaceWinner {
                    carrier: lane.kind.proxy_name().into(),
                    masque_transport: match lane.transport {
                        Some("mim") | None => None,
                        Some(framing) => Some(framing.to_string()),
                    },
                    protocol: match lane.transport {
                        Some("mim") => Some("mim".into()),
                        Some(_) => Some("masque".into()),
                        None => None,
                    },
                    fragment_client_hello: engine.then_some(trial.fragment_client_hello),
                    ech: if engine { trial.ech.clone() } else { None },
                    endpoint_mode: if engine { session_endpoint_mode(&profile) } else { None },
                    seconds: started.elapsed().as_secs(),
                });
                break;
            }
        }

        stop.store(true, Ordering::SeqCst);

        if let (Some(network), Some(path)) = (&network, &memory_path) {
            // The engine lost here only if every one of its lanes said so
            // before the race ended. One still scanning when Psiphon answered
            // has not failed, and marking it would keep a working engine out of
            // the lead for hours.
            let engine_lanes = outcomes.iter().filter(|o| o.carrier == "aether").count();
            let engine_ran = expected_engine_lanes(&profile, &available);
            let engine_failed = engine_ran > 0
                && engine_lanes == engine_ran
                && outcomes
                    .iter()
                    .filter(|o| o.carrier == "aether")
                    .all(|o| o.outcome == "failed");
            let remedy = remedies
                .iter()
                .filter_map(|slot| slot.lock().ok().and_then(|named| *named))
                .last();
            let now = route_memory::now_unix();
            let mut memory = RouteMemory::load(path);
            if let Some(route) = &winner_route {
                memory.record_win(network, route.clone(), now);
            }
            if !winner_route.as_ref().is_some_and(Route::is_engine)
                && (remedy.is_some() || (had_lead && engine_failed))
            {
                memory.record_engine_failure(network, had_lead && engine_failed, remedy, now);
            }
            if let Err(error) = memory.save(path) {
                supervisor.log("warn", format!("searching: could not remember this network: {error}"));
            }
        }

        // Everything this started, stopped -- the winner included. What goes
        // back is the *identity* of the way out, and the ordinary connect path
        // starts it from scratch. See the note at the top of this file.
        app_for_race.state::<crate::psiphon::Psiphon>().stop();
        app_for_race.state::<crate::tor::Tor>().stop();

        // The lanes that were still going are followed on a thread of their
        // own, so the answer is not held up by them and their evidence is not
        // lost either. The first attempt at this waited three seconds inline
        // and got neither: the wait was far too short for a lane inside a probe
        // to notice the stop flag, so the log recorded only the winner -- and a
        // search that cannot say what the other ways out did is a search nobody
        // can check, which is the whole reason these lines exist.
        //
        // Each lane's own process dies with it, so nothing outlives this by
        // more than the one probe it was in the middle of.
        let still_running = expected - outcomes.len();
        if still_running > 0 {
            let supervisor = supervisor.clone();
            thread::spawn(move || {
                for _ in 0..still_running {
                    let Ok((lane, result, seconds)) = receiver.recv_timeout(STRAGGLER_GRACE) else {
                        supervisor.log(
                            "warn",
                            "searching: a way out never reported what it did".into(),
                        );
                        break;
                    };
                    supervisor.log(
                        "info",
                        match &result {
                            Ok(_) => format!(
                                "searching: {} would also have carried, after {seconds}s",
                                lane.name()
                            ),
                            Err(reason) => format!(
                                "searching: {} did not carry after {seconds}s -- {reason}",
                                lane.name()
                            ),
                        },
                    );
                }
            });
        }

        match &winner {
            Some(won) => supervisor.log(
                "info",
                format!("searching: settled on {} after {}s", won.carrier, won.seconds),
            ),
            None => supervisor.log(
                "error",
                "searching: no way out carried traffic; the lines above say how each one failed"
                    .into(),
            ),
        }
        // Back to idle either way. A search that found nothing must not leave
        // the screen looking like something is still coming.
        supervisor.show_search(false, None);

        RaceReport { winner, lanes: outcomes }
    })
    .await
    .map_err(|error| format!("the search did not finish: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn kinds(lanes: &[Lane]) -> Vec<(CarrierKind, Option<&'static str>)> {
        lanes.iter().map(|lane| (lane.kind, lane.transport)).collect()
    }

    #[test]
    fn a_masque_profile_races_both_framings() {
        // H2 and H3 are not interchangeable per network, and which one gets
        // through is not knowable in advance -- so both start.
        let profile = CoreProfile::default();
        let all = [CarrierKind::Aether, CarrierKind::Psiphon, CarrierKind::Tor];
        assert_eq!(
            kinds(&lanes(&profile, &all)),
            vec![
                (CarrierKind::Aether, Some("h2")),
                (CarrierKind::Aether, Some("h3")),
                // Last of the engine's lanes: the slowest, and the one that
                // exists for a network that has learnt to recognise a single
                // MASQUE hop. Raced rather than offered, because on that
                // network it is the only engine lane that gets out and nobody
                // opens Advanced to ask for it.
                (CarrierKind::Aether, Some("mim")),
                (CarrierKind::Psiphon, None),
                (CarrierKind::Tor, None),
            ]
        );
    }

    #[test]
    fn a_fixed_protocol_goes_first_with_both_framings_behind_it() {
        // On a network that blocks WireGuard, a search that raced only
        // WireGuard had nothing else for the engine to try.
        let all = [CarrierKind::Aether, CarrierKind::Psiphon, CarrierKind::Tor];
        for protocol in ["wg", "gool", "mim"] {
            let mut profile = CoreProfile::default();
            profile.protocol = protocol.into();
            assert_eq!(
                kinds(&lanes(&profile, &all)),
                vec![
                    (CarrierKind::Aether, None),
                    (CarrierKind::Aether, Some("h2")),
                    (CarrierKind::Aether, Some("h3")),
                    (CarrierKind::Psiphon, None),
                    (CarrierKind::Tor, None),
                ],
                "{protocol}"
            );
        }
    }

    fn engine_route(transport: &str, fragment: bool, ech: Option<&str>) -> Route {
        Route {
            carrier: "aether".into(),
            protocol: Some("masque".into()),
            transport: Some(transport.into()),
            fragment,
            ech: ech.map(str::to_string),
        }
    }

    fn tactics(lanes: &[Lane]) -> Vec<(Option<&'static str>, bool, Option<String>)> {
        lanes
            .iter()
            .filter(|lane| lane.kind == CarrierKind::Aether)
            .map(|lane| (lane.transport, lane.fragment, lane.ech.clone()))
            .collect()
    }

    #[test]
    fn a_remembered_route_runs_its_lane_with_the_tactic_that_got_it_out() {
        let mut profile = CoreProfile::default();
        profile.fragment_client_hello = false;
        let mut raced = lanes(&profile, &[CarrierKind::Aether]);
        let recall = Recall { engine_route: Some(engine_route("h2", true, None)), remedy: None };
        assert!(apply_recall(&mut raced, &profile, &recall));
        assert_eq!(
            tactics(&raced),
            vec![(Some("h2"), true, None), (Some("h3"), false, None), (Some("mim"), false, None)]
        );
        // And the lane really runs it, whatever the profile says.
        assert!(trial_profile(&profile, &raced[0]).args(Path::new("i.toml")).contains(&"--fragment".into()));
    }

    #[test]
    fn nothing_remembered_leaves_every_lane_plain() {
        let profile = CoreProfile::default();
        let mut raced = lanes(&profile, &[CarrierKind::Aether]);
        assert!(!apply_recall(&mut raced, &profile, &Recall::default()));
        assert!(raced.iter().all(|lane| !lane.fragment && lane.ech.is_none()));
    }

    #[test]
    fn a_failure_that_names_its_remedy_sends_it_to_the_lane_that_can_use_it() {
        let profile = CoreProfile::default();

        let mut raced = lanes(&profile, &[CarrierKind::Aether]);
        apply_recall(&mut raced, &profile, &Recall { engine_route: None, remedy: Some(Remedy::Ech) });
        assert_eq!(
            tactics(&raced),
            vec![
                (Some("h2"), false, None),
                (Some("h3"), false, Some("require".into())),
                (Some("mim"), false, None)
            ]
        );

        let mut raced = lanes(&profile, &[CarrierKind::Aether]);
        apply_recall(
            &mut raced,
            &profile,
            &Recall { engine_route: None, remedy: Some(Remedy::Fragment) },
        );
        assert_eq!(
            tactics(&raced),
            vec![(Some("h2"), true, None), (Some("h3"), false, None), (Some("mim"), false, None)]
        );
    }

    #[test]
    fn a_route_is_remembered_from_what_the_lane_ran_not_from_its_name() {
        // Split by the user's own setting on a plain H2 lane: remembered as
        // split, because that is what got out.
        let profile = CoreProfile::default();
        assert!(profile.fragment_client_hello);
        let h2 = Lane::plain(CarrierKind::Aether, Some("h2"));
        assert_eq!(
            route_of(CarrierKind::Aether, &trial_profile(&profile, &h2)),
            engine_route("h2", true, None)
        );

        // A setting the framing ignores is not part of what worked: H3 does
        // not split, and H2 does not carry ECH.
        let mut profile = CoreProfile::default();
        profile.ech = Some("auto".into());
        let h3 = Lane::plain(CarrierKind::Aether, Some("h3"));
        assert_eq!(
            route_of(CarrierKind::Aether, &trial_profile(&profile, &h3)),
            engine_route("h3", false, Some("auto"))
        );
        assert_eq!(
            route_of(CarrierKind::Aether, &trial_profile(&profile, &h2)).ech,
            None
        );
    }

    #[test]
    fn a_search_is_not_held_open_by_a_deep_scan() {
        let lane = Lane::plain(CarrierKind::Aether, Some("h2"));
        for (mode, raced) in [
            ("turbo", "turbo"),
            ("balanced", "balanced"),
            ("thorough", "balanced"),
            ("stealth", "balanced"),
            ("ironclad", "balanced"),
        ] {
            let mut profile = CoreProfile::default();
            profile.scan_mode = mode.into();
            assert_eq!(trial_profile(&profile, &lane).scan_mode, raced, "{mode}");
        }
    }

    #[test]
    fn a_pinned_endpoint_does_not_pin_the_search() {
        let mut profile = CoreProfile::default();
        profile.endpoint_mode = "custom-only".into();
        profile.peer = Some("162.159.198.1:443".into());
        let lane = Lane::plain(CarrierKind::Aether, Some("h2"));
        let args = trial_profile(&profile, &lane).args(Path::new("i.toml"));
        assert!(!args.contains(&"--peer".to_string()), "{args:?}");
        // The session after a win still tries the pin first.
        assert_eq!(session_endpoint_mode(&profile).as_deref(), Some("custom-first"));
        profile.endpoint_mode = "custom-first".into();
        assert_eq!(session_endpoint_mode(&profile), None);
    }

    #[test]
    fn a_carrier_that_is_not_installed_gets_no_lane() {
        // Starting it would spend a thread on a certainty, and the arm64 Linux
        // build genuinely ships without Tor.
        let profile = CoreProfile::default();
        let lanes = lanes(&profile, &[CarrierKind::Aether, CarrierKind::Psiphon]);
        assert!(lanes.iter().all(|lane| lane.kind != CarrierKind::Tor));
        // Three engine framings plus Psiphon.
        assert_eq!(lanes.len(), 4);

        assert!(lanes_for_nothing_installed().is_empty());
    }

    fn lanes_for_nothing_installed() -> Vec<Lane> {
        lanes(&CoreProfile::default(), &[])
    }

    #[test]
    fn every_lane_gets_at_least_the_deadline_its_carrier_enforces_on_itself() {
        // A lane cut below these answers "no" for a carrier that was still
        // working, which is the one thing this must never do.
        let profile = CoreProfile::default();
        assert!(lane_budget(CarrierKind::Psiphon, &profile) >= Duration::from_secs(315));
        assert!(lane_budget(CarrierKind::Tor, &profile) >= Duration::from_secs(180));
        assert!(lane_budget(CarrierKind::Aether, &profile) >= Duration::from_secs(170));
    }

    #[test]
    fn two_free_ports_in_a_row_do_not_collide() {
        // Two engine lanes start within milliseconds of each other.
        assert_ne!(free_port().unwrap(), free_port().unwrap());
    }
}
