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

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::carrier::CarrierKind;
use crate::carrier_probe::carries_verified_traffic_unless;
use crate::core_supervisor::{engine_command, resolve_core_path, CoreProfile, CoreSupervisor};

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
    /// How long it took to answer, for the line that says so on screen.
    pub seconds: u64,
}

/// One thing the race will try.
#[derive(Debug, Clone, Copy)]
struct Lane {
    kind: CarrierKind,
    /// Only meaningful for the engine.
    transport: Option<&'static str>,
}

impl Lane {
    /// How this lane is named in the log, framing included.
    fn name(&self) -> String {
        match self.transport {
            Some(transport) => format!("{} {transport}", self.kind.proxy_name()),
            None => self.kind.proxy_name().to_string(),
        }
    }
}

/// The lanes to run, given what is installed and what the profile asks for.
///
/// Both MASQUE framings when the profile is on MASQUE, because H2 and H3 are
/// not interchangeable per network -- one user's Wi-Fi reached Cloudflare over
/// QUIC only, while the known mobile case is the opposite -- and the retry
/// machinery already alternates them for exactly that reason. A profile on
/// WireGuard or WARP-in-WARP gets the one lane it chose, which is the same rule
/// `profile_for_attempt` follows: a single-transport protocol is left alone.
fn lanes(profile: &CoreProfile, available: &[CarrierKind]) -> Vec<Lane> {
    let mut lanes = Vec::new();
    if available.contains(&CarrierKind::Aether) {
        if profile.protocol == "masque" {
            lanes.push(Lane { kind: CarrierKind::Aether, transport: Some("h2") });
            lanes.push(Lane { kind: CarrierKind::Aether, transport: Some("h3") });
            // Two nested MASQUE hops, raced last among the engine's lanes
            // because it is the slowest and the most work. It exists for the
            // network that has learnt to recognise a single MASQUE hop, and on
            // that network it is the only engine lane that can get out -- so it
            // has to be tried without anybody knowing to ask for it. Nobody
            // opens Advanced.
            lanes.push(Lane { kind: CarrierKind::Aether, transport: Some("mim") });
        } else {
            lanes.push(Lane { kind: CarrierKind::Aether, transport: None });
        }
    }
    for kind in [CarrierKind::Psiphon, CarrierKind::Tor] {
        if available.contains(&kind) {
            lanes.push(Lane { kind, transport: None });
        }
    }
    lanes
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
    lane: Lane,
    profile: &CoreProfile,
    stop: &AtomicBool,
) -> Result<SocketAddr, String> {
    let deadline = Instant::now() + lane_budget(lane.kind, profile);

    // Whatever this lane started, so it can be asked whether it is carrying
    // yet. The engine keeps its child alive in `_engine` for the whole lane.
    let (listener, _engine) = match lane.kind {
        CarrierKind::Aether => {
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
            // Its own listener, so two engine lanes and whatever the user
            // already has running never contend for one port.
            let port = free_port()?;
            trial.socks_address = format!("127.0.0.1:{port}");
            // A trial is not a session: it retries nothing, because the race's
            // own deadline is the only budget that should apply here.
            trial.auto_reconnect = false;

            let core_path = resolve_core_path(app, profile.core_path.as_deref())?;
            let mut command = engine_command(app, &trial, &core_path)?;
            let child = command
                .spawn()
                .map_err(|error| format!("failed to start a trial engine: {error}"))?;
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
    let lanes = lanes(&profile, &available);
    if lanes.is_empty() {
        return Ok(RaceReport { winner: None, lanes: Vec::new() });
    }

    let supervisor = supervisor.inner().clone();
    let app_for_race = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let started = Instant::now();
        let stop = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel::<(Lane, Result<SocketAddr, String>, u64)>();
        let expected = lanes.len();

        supervisor.show_search(true, Some(format!("Trying {expected} ways out at once")));
        supervisor.log(
            "info",
            format!(
                "searching: {} started together",
                lanes.iter().map(Lane::name).collect::<Vec<_>>().join(", ")
            ),
        );

        for lane in lanes {
            let app = app_for_race.clone();
            let profile = profile.clone();
            let stop = stop.clone();
            let sender = sender.clone();
            thread::spawn(move || {
                let began = Instant::now();
                let outcome = run_lane(&app, lane, &profile, &stop);
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
                    seconds: started.elapsed().as_secs(),
                });
                break;
            }
        }

        stop.store(true, Ordering::SeqCst);

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
    fn a_single_transport_protocol_is_left_alone() {
        // The same rule the retry machinery follows: WireGuard has no second
        // framing to alternate with, so substituting one would be answering a
        // question nobody asked.
        let mut profile = CoreProfile::default();
        profile.protocol = "wg".into();
        let all = [CarrierKind::Aether, CarrierKind::Psiphon, CarrierKind::Tor];
        assert_eq!(
            kinds(&lanes(&profile, &all)),
            vec![
                (CarrierKind::Aether, None),
                (CarrierKind::Psiphon, None),
                (CarrierKind::Tor, None),
            ]
        );
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
